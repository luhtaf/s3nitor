package async

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// fakeCollector answers Poll with whatever the test set.
type fakeCollector struct {
	name  string
	calls atomic.Int64

	mu     sync.Mutex
	result scanner.Result
	done   bool
	err    error
}

func (f *fakeCollector) Name() string { return f.name }

func (f *fakeCollector) Poll(context.Context, string) (scanner.Result, bool, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.result, f.done, f.err
}

func (f *fakeCollector) set(res scanner.Result, done bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result, f.done, f.err = res, done, err
}

type recordingReporter struct {
	mu   sync.Mutex
	docs []*scanner.Finding
}

func (r *recordingReporter) Report(_ context.Context, f *scanner.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs = append(r.docs, f)
	return nil
}

func (r *recordingReporter) all() []*scanner.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*scanner.Finding(nil), r.docs...)
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db") + "?_journal_mode=WAL&_busy_timeout=5000"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb
}

func testContinuation() Continuation {
	return Continuation{
		FileID: "f1", Bucket: "b", Key: "dir/sample.bin", Version: "v1", Size: 42,
		Hashes:       map[string]string{"sha256": "abc"},
		Scanner:      "cape",
		RulesVersion: "cape",
		Token:        "task-417",
		SubmittedAt:  time.Now().Add(-time.Minute),
	}
}

func newTestWorker(t *testing.T, gdb *gorm.DB, rep *recordingReporter, col Collector) *Worker {
	t.Helper()
	return NewWorker(gdb, rep, nil, []Collector{col}, WorkerOptions{
		Instance:     "test",
		PollInterval: time.Minute,
		MaxAge:       time.Hour,
	})
}

// An analysis still running must publish nothing and stay claimable.
func TestUnfinishedAnalysisPublishesNothing(t *testing.T) {
	gdb, rep := testDB(t), &recordingReporter{}
	col := &fakeCollector{name: "cape"}
	col.set(scanner.Result{}, false, nil)

	c := testContinuation()
	if err := db.EnqueueContinuation(gdb, c.FileID, c.Scanner, c.RulesVersion, c.Token, 0); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	newTestWorker(t, gdb, rep, col).handle(context.Background(), c)

	if n := len(rep.all()); n != 0 {
		t.Errorf("published %d documents, want 0 — a running analysis is not a verdict", n)
	}
	var task db.ScanTask
	if err := gdb.First(&task).Error; err != nil {
		t.Fatalf("reading task: %v", err)
	}
	if task.Status != db.StatusPending {
		t.Errorf("status = %q, want pending — the task must stay collectable", task.Status)
	}
	if task.ResumeToken != c.Token {
		t.Errorf("resume token = %q, want %q", task.ResumeToken, c.Token)
	}
}

// A finished analysis publishes exactly one document and closes the ledger row.
func TestFinishedAnalysisPublishesAndClosesTheTask(t *testing.T) {
	gdb, rep := testDB(t), &recordingReporter{}
	col := &fakeCollector{name: "cape"}
	col.set(scanner.Result{
		Match: true, Severity: scanner.SeverityHigh,
		Detail: map[string]any{"score": 7.5},
	}, true, nil)

	c := testContinuation()
	if err := db.EnqueueContinuation(gdb, c.FileID, c.Scanner, c.RulesVersion, c.Token, 0); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	newTestWorker(t, gdb, rep, col).handle(context.Background(), c)

	docs := rep.all()
	if len(docs) != 1 {
		t.Fatalf("published %d documents, want 1", len(docs))
	}
	got := docs[0]
	if got.Scanner != "cape" || !got.Match || got.Severity != scanner.SeverityHigh {
		t.Errorf("document = %+v, want a matching high finding from cape", got)
	}
	// The identity fields have to survive the handoff, or the verdict cannot be
	// tied back to the object it belongs to.
	if got.Bucket != "b" || got.Key != "dir/sample.bin" || got.FileID != "f1" {
		t.Errorf("document lost the object's identity: %+v", got)
	}

	var task db.ScanTask
	if err := gdb.First(&task).Error; err != nil {
		t.Fatalf("reading task: %v", err)
	}
	if task.Status != db.StatusDone {
		t.Errorf("status = %q, want done", task.Status)
	}
}

// The document a resumed scan publishes must be the one the inline path would
// have published, so a replay overwrites rather than duplicates.
func TestResumedDocumentHasTheSameIDAsAnInlineOne(t *testing.T) {
	c := testContinuation()
	res := scanner.Result{Match: true, Severity: scanner.SeverityHigh}

	in := &scanner.ScanInput{
		FileID: c.FileID, Bucket: c.Bucket, Key: c.Key,
		Version: c.Version, Size: c.Size, Hashes: c.Hashes,
	}
	inline := scanner.NewFindingFor(in, c.Scanner, c.RulesVersion, res, nil)
	resumed := c.Finding(res, nil)

	if inline.DocID() != resumed.DocID() {
		t.Errorf("DocID differs between paths:\n  inline  %s\n  resumed %s\n"+
			"at-least-once delivery then duplicates instead of overwriting",
			inline.DocID(), resumed.DocID())
	}
}

// An analysis that never finishes must be abandoned with a document saying so.
//
// Left polling, the task stays pending forever and publishes nothing — and
// nothing is indistinguishable from a clean verdict for anyone reading the
// index.
func TestStaleAnalysisIsAbandonedWithADocument(t *testing.T) {
	gdb, rep := testDB(t), &recordingReporter{}
	col := &fakeCollector{name: "cape"}
	col.set(scanner.Result{}, false, nil)

	c := testContinuation()
	c.SubmittedAt = time.Now().Add(-2 * time.Hour) // older than MaxAge
	if err := db.EnqueueContinuation(gdb, c.FileID, c.Scanner, c.RulesVersion, c.Token, 0); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	newTestWorker(t, gdb, rep, col).handle(context.Background(), c)

	if col.calls.Load() != 0 {
		t.Error("an abandoned analysis should not be polled again")
	}
	docs := rep.all()
	if len(docs) != 1 {
		t.Fatalf("published %d documents, want 1 saying the analysis never finished", len(docs))
	}
	if docs[0].Error == "" {
		t.Error("the document must carry the reason, or it reads as a clean scan")
	}
	var task db.ScanTask
	gdb.First(&task)
	if task.Status != db.StatusFailed {
		t.Errorf("status = %q, want failed", task.Status)
	}
}

// A continuation naming a scanner this worker cannot read must not spin.
func TestUnknownScannerFailsRatherThanLooping(t *testing.T) {
	gdb, rep := testDB(t), &recordingReporter{}
	col := &fakeCollector{name: "cape"}

	c := testContinuation()
	c.Scanner = "cuckoo" // not registered here
	if err := db.EnqueueContinuation(gdb, c.FileID, c.Scanner, c.RulesVersion, c.Token, 0); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	newTestWorker(t, gdb, rep, col).handle(context.Background(), c)

	if len(rep.all()) != 1 {
		t.Fatalf("published %d documents, want 1 explaining the gap", len(rep.all()))
	}
	var task db.ScanTask
	gdb.First(&task)
	if task.Status != db.StatusFailed {
		t.Errorf("status = %q, want failed", task.Status)
	}
}

// A continuation whose poll time has not arrived is left alone.
//
// Kafka has no delayed delivery, so an early message is put back on the
// ledger's clock. Sleeping here instead would block every other continuation on
// the same partition behind the slowest analysis.
func TestEarlyContinuationIsNotPolled(t *testing.T) {
	gdb, rep := testDB(t), &recordingReporter{}
	col := &fakeCollector{name: "cape"}
	col.set(scanner.Result{}, true, nil)

	c := testContinuation()
	c.PollAfter = time.Now().Add(time.Hour)

	newTestWorker(t, gdb, rep, col).handle(context.Background(), c)

	if col.calls.Load() != 0 {
		t.Errorf("polled %d times before poll_after, want 0", col.calls.Load())
	}
	if n := len(rep.all()); n != 0 {
		t.Errorf("published %d documents, want 0", n)
	}
}
