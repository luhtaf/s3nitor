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

// recordingReporter captures what the publish stage emitted.
type recordingReporter struct {
	mu      sync.Mutex
	docs    []*scanner.FileResult
	batches atomic.Int64
}

func (r *recordingReporter) Report(_ context.Context, fr *scanner.FileResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs = append(r.docs, fr)
	r.batches.Add(1)
	return nil
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
	p := New(cfg, opener, scanner.NewEngine(&config.Config{}), rep, testDB(t), metrics.New(), t.TempDir())

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
	p := New(cfg, opener, scanner.NewEngine(&config.Config{}), rep, testDB(t), metrics.New(), t.TempDir())

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
	p := New(cfg, opener, scanner.NewEngine(&config.Config{}), rep, testDB(t), metrics.New(), t.TempDir())

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
	if opener.peakBytes() > 100 {
		t.Error("the oversized object was transferred despite being over the limit")
	}

	var gaps int
	for _, doc := range rep.docs {
		res, ok := doc.Results["size_gate"]
		if !ok {
			continue
		}
		gaps++
		if doc.Key != "big" {
			t.Errorf("coverage gap reported for %q, want \"big\"", doc.Key)
		}
		if scanned, _ := res.Detail["scanned"].(bool); scanned {
			t.Error("coverage gap claims the object was scanned")
		}
		if got, _ := res.Detail["object_size"].(int64); got != 5000 {
			t.Errorf("coverage gap object_size = %v, want 5000", res.Detail["object_size"])
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
	p1 := New(cfg, &fakeOpener{sizes: sizes}, scanner.NewEngine(&config.Config{}), first, gdb, metrics.New(), t.TempDir())
	if _, err := p1.Run(context.Background(), objs); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.count() != 2 {
		t.Fatalf("first run published %d, want 2", first.count())
	}

	second := &recordingReporter{}
	opener2 := &fakeOpener{sizes: sizes}
	p2 := New(cfg, opener2, scanner.NewEngine(&config.Config{}), second, gdb, metrics.New(), t.TempDir())
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
	p3 := New(cfg, &fakeOpener{sizes: sizes}, scanner.NewEngine(&config.Config{}), third, gdb, metrics.New(), t.TempDir())
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
	p := New(cfg, &fakeOpener{sizes: sizes}, scanner.NewEngine(&config.Config{}), rep, testDB(t), metrics.New(), t.TempDir())

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
		scanner.NewEngine(&config.Config{}), rep, testDB(t), metrics.New(), workDir)

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
