package pipeline

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// fakeOpener serves objects from memory and tracks how many bytes are being
// read at once, which is what the byte budget is supposed to bound.
type fakeOpener struct {
	sizes map[string]int64
	delay time.Duration

	mu      sync.Mutex
	current int64
	peak    int64
}

func (f *fakeOpener) Open(_ context.Context, key string) (io.ReadCloser, error) {
	size, ok := f.sizes[key]
	if !ok {
		return nil, fmt.Errorf("no such object: %s", key)
	}

	f.mu.Lock()
	f.current += size
	if f.current > f.peak {
		f.peak = f.current
	}
	f.mu.Unlock()

	// Hold the object open briefly so concurrent transfers actually overlap;
	// without this the test could pass by never running two at once.
	time.Sleep(f.delay)

	return &trackedReader{
		Reader: strings.NewReader(strings.Repeat("x", int(size))),
		done: func() {
			f.mu.Lock()
			f.current -= size
			f.mu.Unlock()
		},
	}, nil
}

func (f *fakeOpener) peakBytes() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peak
}

type trackedReader struct {
	io.Reader
	once sync.Once
	done func()
}

func (r *trackedReader) Close() error {
	r.once.Do(r.done)
	return nil
}

// fakeScanner stands in for a real scanner so a test can control exactly what
// runs, whether it touches the payload, and how long it takes.
type fakeScanner struct {
	name        string
	needsFile   bool
	delay       time.Duration
	calls       atomic.Int64
	sawPayload  atomic.Int64
	missingFile atomic.Int64
}

func (f *fakeScanner) Name() string         { return f.name }
func (f *fakeScanner) Enabled() bool        { return true }
func (f *fakeScanner) NeedsPayload() bool   { return f.needsFile }
func (f *fakeScanner) RulesVersion() string { return "v1" }

func (f *fakeScanner) Scan(_ context.Context, in *scanner.ScanInput) (scanner.Result, error) {
	f.calls.Add(1)
	if f.needsFile {
		if _, err := os.Stat(in.LocalPath); err == nil {
			f.sawPayload.Add(1)
		} else {
			// The payload was freed while a scanner that needs it was still
			// running — a refcounting bug, and one that would otherwise show up
			// only as mysteriously empty scan results.
			f.missingFile.Add(1)
		}
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return scanner.Result{Match: false, Severity: scanner.SeverityInfo}, nil
}

// recordingReporter captures what the publish stage emitted.
type recordingReporter struct {
	mu      sync.Mutex
	docs    []*scanner.Finding
	batches atomic.Int64
}

func (r *recordingReporter) Report(_ context.Context, f *scanner.Finding) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs = append(r.docs, f)
	r.batches.Add(1)
	return nil
}

// findingsFor counts documents produced by one scanner.
func (r *recordingReporter) findingsFor(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, d := range r.docs {
		if d.Scanner == name {
			n++
		}
	}
	return n
}

func (r *recordingReporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.docs)
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	// A file in the test's temp dir rather than :memory:, because an in-memory
	// database is per-connection and the pool opens several.
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

func testConfig() *config.Config {
	return &config.Config{
		FetchByteBudget:      4096,
		FetchMaxConns:        8,
		AnalyzeCPULimit:      4,
		PublishBatchSize:     10,
		PublishFlushInterval: 50 * time.Millisecond,
		PublishMaxBytes:      1 << 20,
		StageQueueSize:       64,
	}
}

// The claim the whole redesign rests on: what is bounded is bytes in flight,
// not the number of files. With 40 objects of 1 KB against a 4 KB budget, no
// more than roughly 4 KB may be moving at once — even though there are eight
// connection slots, which under a file-count limit would have allowed 8 KB.
func TestByteBudgetBoundsBytesInFlight(t *testing.T) {
	const (
		objects    = 40
		objectSize = 1024
		budget     = 4096
	)

	cfg := testConfig()
	cfg.FetchByteBudget = budget

	sizes := make(map[string]int64, objects)
	objs := make([]s3fetcher.S3Object, 0, objects)
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("obj-%03d", i)
		sizes[key] = objectSize
		objs = append(objs, s3fetcher.S3Object{
			Bucket: "b", Key: key, ETag: fmt.Sprintf("etag-%d", i), Size: objectSize,
		})
	}

	opener := &fakeOpener{sizes: sizes, delay: 2 * time.Millisecond}
	rep := &recordingReporter{}
	p := New(cfg, opener, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), rep, testDB(t), metrics.New(), t.TempDir())

	if _, err := p.Run(context.Background(), objs); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if peak := opener.peakBytes(); peak > budget {
		t.Errorf("peak bytes in flight = %d, budget = %d", peak, budget)
	}
	if got := rep.count(); got != objects {
		t.Errorf("published %d documents, want %d", got, objects)
	}
	if p.byteLimiter.InFlight() != 0 {
		t.Errorf("byte budget leaked %d bytes", p.byteLimiter.InFlight())
	}
}

// A single object larger than the entire budget must still be scanned. Passing
// its size straight to a weighted semaphore would block until the context died.
func TestObjectLargerThanBudgetStillCompletes(t *testing.T) {
	cfg := testConfig()
	cfg.FetchByteBudget = 512

	opener := &fakeOpener{sizes: map[string]int64{"huge": 8192}}
	rep := &recordingReporter{}
	p := New(cfg, opener, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), rep, testDB(t), metrics.New(), t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := p.Run(ctx, []s3fetcher.S3Object{
		{Bucket: "b", Key: "huge", ETag: "e", Size: 8192},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.count() != 1 {
		t.Errorf("published %d documents, want 1", rep.count())
	}
}

// Objects past MAX_OBJECT_SIZE are skipped before anything is transferred.
func TestMaxObjectSizeSkipsBeforeFetching(t *testing.T) {
	cfg := testConfig()
	cfg.MaxObjectSize = 1000

	opener := &fakeOpener{sizes: map[string]int64{"small": 100, "big": 5000}}
	rep := &recordingReporter{}
	p := New(cfg, opener, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), rep, testDB(t), metrics.New(), t.TempDir())

	if _, err := p.Run(context.Background(), []s3fetcher.S3Object{
		{Bucket: "b", Key: "small", ETag: "e1", Size: 100},
		{Bucket: "b", Key: "big", ETag: "e2", Size: 5000},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Two documents: the scan of the small object, and a coverage notice saying
	// the large one was never looked at. Skipping silently would hide the gap.
	if rep.count() != 2 {
		t.Fatalf("published %d documents, want 2 (one scan, one coverage gap)", rep.count())
	}
	if got := rep.findingsFor("test"); got != 1 {
		t.Errorf("the scanner produced %d findings, want 1", got)
	}
	if opener.peakBytes() > 100 {
		t.Error("the oversized object was transferred despite being over the limit")
	}

	var gaps int
	for _, doc := range rep.docs {
		if doc.Scanner != "size_gate" {
			continue
		}
		gaps++
		if doc.Key != "big" {
			t.Errorf("coverage gap reported for %q, want \"big\"", doc.Key)
		}
		if scanned, _ := doc.Detail["scanned"].(bool); scanned {
			t.Error("coverage gap claims the object was scanned")
		}
		if got, _ := doc.Detail["object_size"].(int64); got != 5000 {
			t.Errorf("coverage gap object_size = %v, want 5000", doc.Detail["object_size"])
		}
	}
	if gaps != 1 {
		t.Errorf("got %d coverage gaps, want 1", gaps)
	}
}

// Dedup must survive a restart: the second run should find everything already
// recorded and transfer nothing.
func TestSecondRunSkipsAlreadyScannedObjects(t *testing.T) {
	cfg := testConfig()
	gdb := testDB(t)

	objs := []s3fetcher.S3Object{
		{Bucket: "b", Key: "a", ETag: "e1", Size: 64},
		{Bucket: "b", Key: "c", ETag: "e2", Size: 64},
	}
	sizes := map[string]int64{"a": 64, "c": 64}

	first := &recordingReporter{}
	p1 := New(cfg, &fakeOpener{sizes: sizes}, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), first, gdb, metrics.New(), t.TempDir())
	if _, err := p1.Run(context.Background(), objs); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.count() != 2 {
		t.Fatalf("first run published %d, want 2", first.count())
	}

	second := &recordingReporter{}
	opener2 := &fakeOpener{sizes: sizes}
	p2 := New(cfg, opener2, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), second, gdb, metrics.New(), t.TempDir())
	if _, err := p2.Run(context.Background(), objs); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.count() != 0 {
		t.Errorf("second run published %d documents, want 0", second.count())
	}
	if opener2.peakBytes() != 0 {
		t.Error("second run transferred data for objects already scanned")
	}

	// A changed ETag is a different version, so it must be scanned again.
	third := &recordingReporter{}
	p3 := New(cfg, &fakeOpener{sizes: sizes}, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), third, gdb, metrics.New(), t.TempDir())
	if _, err := p3.Run(context.Background(), []s3fetcher.S3Object{
		{Bucket: "b", Key: "a", ETag: "CHANGED", Size: 64},
	}); err != nil {
		t.Fatalf("third run: %v", err)
	}
	if third.count() != 1 {
		t.Errorf("a changed ETag published %d documents, want 1", third.count())
	}
}

// Shutdown must drain the partial batch. Without it a run ending on a
// half-filled batch discards findings that were already computed.
func TestPartialBatchIsFlushedOnShutdown(t *testing.T) {
	cfg := testConfig()
	cfg.PublishBatchSize = 100                // never reached
	cfg.PublishFlushInterval = 10 * time.Hour // never fires

	sizes := map[string]int64{}
	var objs []s3fetcher.S3Object
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("k%d", i)
		sizes[key] = 32
		objs = append(objs, s3fetcher.S3Object{Bucket: "b", Key: key, ETag: key, Size: 32})
	}

	rep := &recordingReporter{}
	p := New(cfg, &fakeOpener{sizes: sizes}, scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), rep, testDB(t), metrics.New(), t.TempDir())

	if _, err := p.Run(context.Background(), objs); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.count() != 3 {
		t.Errorf("published %d documents, want 3 — the partial batch was dropped", rep.count())
	}
}

// The budget has to cover disk residency, not just the transfer.
//
// An earlier version released it the moment the transfer finished, so a slow
// analyze stage let fetched files pile up on disk while the accounting said the
// budget was free — bounded only by the channel buffer, which is a count and not
// a size. With a slow scanner and a budget of two objects, no more than two
// payloads may exist at once.
func TestBudgetCoversDiskResidencyNotJustTransfer(t *testing.T) {
	const (
		objects    = 12
		objectSize = 512
		budget     = objectSize * 2
	)

	cfg := testConfig()
	cfg.FetchByteBudget = budget
	cfg.FetchMaxConns = 8    // deliberately more slots than the budget allows
	cfg.AnalyzeCPULimit = 1  // one slow scanner, so payloads would queue up
	cfg.StageQueueSize = 100 // a count-based bound would permit 100 files here

	sizes := make(map[string]int64, objects)
	objs := make([]s3fetcher.S3Object, 0, objects)
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("obj-%02d", i)
		sizes[key] = objectSize
		objs = append(objs, s3fetcher.S3Object{
			Bucket: "b", Key: key, ETag: key, Size: objectSize,
		})
	}

	workDir := t.TempDir()
	rep := &recordingReporter{}
	p := New(cfg, &fakeOpener{sizes: sizes, delay: time.Millisecond},
		scanner.NewEngineWith(&fakeScanner{name: "test", needsFile: true}), rep, testDB(t), metrics.New(), workDir)

	// Watch the work directory while the run proceeds.
	var peakFiles int64
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if entries, err := os.ReadDir(workDir); err == nil {
				if n := int64(len(entries)); n > atomic.LoadInt64(&peakFiles) {
					atomic.StoreInt64(&peakFiles, n)
				}
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()

	if _, err := p.Run(context.Background(), objs); err != nil {
		t.Fatalf("Run: %v", err)
	}
	close(stop)
	watcher.Wait()

	if peak := atomic.LoadInt64(&peakFiles); peak > budget/objectSize {
		t.Errorf("peak payloads on disk = %d, budget allows %d", peak, budget/objectSize)
	}
	if rep.count() != objects {
		t.Errorf("published %d documents, want %d", rep.count(), objects)
	}
	if p.byteLimiter.InFlight() != 0 {
		t.Errorf("byte budget leaked %d bytes", p.byteLimiter.InFlight())
	}
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Errorf("%d payloads left behind", len(left))
	}
}

// One object, several scanners: each verdict is published on its own, and the
// payload survives until the last scanner that reads it is finished.
func TestEachScannerPublishesItsOwnFinding(t *testing.T) {
	cfg := testConfig()

	fast := &fakeScanner{name: "fast", needsFile: false}
	slow := &fakeScanner{name: "slow", needsFile: true, delay: 5 * time.Millisecond}
	other := &fakeScanner{name: "other", needsFile: true}

	const objects = 6
	sizes := map[string]int64{}
	var objs []s3fetcher.S3Object
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("k%02d", i)
		sizes[key] = 128
		objs = append(objs, s3fetcher.S3Object{Bucket: "b", Key: key, ETag: key, Size: 128})
	}

	workDir := t.TempDir()
	rep := &recordingReporter{}
	p := New(cfg, &fakeOpener{sizes: sizes},
		scanner.NewEngineWith(fast, slow, other), rep, testDB(t), metrics.New(), workDir)

	if _, err := p.Run(context.Background(), objs); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := rep.count(); got != objects*3 {
		t.Errorf("published %d documents, want %d (one per object per scanner)", got, objects*3)
	}
	for _, s := range []*fakeScanner{fast, slow, other} {
		if got := rep.findingsFor(s.name); got != objects {
			t.Errorf("scanner %q produced %d findings, want %d", s.name, got, objects)
		}
	}

	// The refcount has to hold the file for every scanner that reads it, not
	// just the first one to finish.
	for _, s := range []*fakeScanner{slow, other} {
		if n := s.missingFile.Load(); n != 0 {
			t.Errorf("scanner %q found the payload already deleted %d times", s.name, n)
		}
		if got := s.sawPayload.Load(); got != objects {
			t.Errorf("scanner %q saw the payload %d times, want %d", s.name, got, objects)
		}
	}

	if p.byteLimiter.InFlight() != 0 {
		t.Errorf("byte budget leaked %d bytes", p.byteLimiter.InFlight())
	}
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Errorf("%d payloads left behind", len(left))
	}
}

// A quota-bound scanner must not hold up the local ones. Its lane is rate
// limited and spills when the queue backs up, so the fast scanners finish while
// the slow one is parked for later.
func TestSpillLaneDoesNotBlockLocalScanners(t *testing.T) {
	cfg := testConfig()
	cfg.SpillScanners = []string{"quota"}
	cfg.ScannerRatePerMin = map[string]float64{"quota": 1} // one per minute
	cfg.StageQueueSize = 2                                 // fills almost immediately

	local := &fakeScanner{name: "local", needsFile: true}
	quota := &fakeScanner{name: "quota", needsFile: false}

	const objects = 20
	sizes := map[string]int64{}
	var objs []s3fetcher.S3Object
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("q%02d", i)
		sizes[key] = 64
		objs = append(objs, s3fetcher.S3Object{Bucket: "b", Key: key, ETag: key, Size: 64})
	}

	gdb := testDB(t)
	rep := &recordingReporter{}
	p := New(cfg, &fakeOpener{sizes: sizes},
		scanner.NewEngineWith(local, quota), rep, gdb, metrics.New(), t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	summary, err := p.Run(ctx, objs)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The local scanner is unaffected by the other lane's quota.
	if got := rep.findingsFor("local"); got != objects {
		t.Errorf("local scanner produced %d findings, want %d", got, objects)
	}

	// At one request per minute the quota lane cannot have run them all, so most
	// must have been parked rather than dropped or waited on.
	if summary.Spilled == 0 {
		t.Fatal("nothing spilled — the quota lane blocked instead of parking work")
	}

	var pending int64
	if err := gdb.Model(&db.ScanTask{}).
		Where("scanner = ? AND status = ?", "quota", db.StatusPending).
		Count(&pending).Error; err != nil {
		t.Fatalf("counting pending: %v", err)
	}
	if pending == 0 {
		t.Error("spilled tasks were not durable — nothing in scan_tasks")
	}
	t.Logf("local=%d quota=%d spilled=%d pending_rows=%d",
		rep.findingsFor("local"), rep.findingsFor("quota"), summary.Spilled, pending)
}

// A spilled task is claimable afterwards, with its lease and attempt count
// tracked — that is what lets a later run finish the work.
func TestPendingTasksAreClaimable(t *testing.T) {
	gdb := testDB(t)

	if err := db.EnqueuePending(gdb, "file-1", "virustotal", "v1", -time.Minute); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	claimed, err := db.ClaimPending(gdb, "instance-a", time.Minute, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed %d tasks, want 1", len(claimed))
	}
	if claimed[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1", claimed[0].Attempts)
	}

	// Already leased, so a second instance must not take the same work.
	again, err := db.ClaimPending(gdb, "instance-b", time.Minute, 10)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("a live lease was stolen: %d tasks claimed", len(again))
	}
}
