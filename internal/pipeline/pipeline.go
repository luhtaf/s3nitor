package pipeline

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/hashing"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// Stage names, used as metric labels.
const (
	stageDiscover = "discover"
	stageFetch    = "fetch"
	stageAnalyze  = "analyze"
	stagePublish  = "publish"
)

// ObjectOpener is the slice of the S3 client this package needs.
//
// An interface rather than the concrete fetcher so the pipeline can be exercised
// without a bucket — the byte budget is the central claim of this design, and a
// claim that can only be checked against live infrastructure is not really
// checked.
type ObjectOpener interface {
	Open(ctx context.Context, key string) (io.ReadCloser, error)
}

// job carries an object from discovery to fetch.
type job struct {
	obj    s3fetcher.S3Object
	fileID string
}

// Pipeline runs the scan as four stages connected by bounded channels.
//
//	discover ─► fetch+hash ─► analyze ─► publish
//	   1 goroutine   bytes      cores     batched
//
// The boundaries follow one rule: a stage exists to separate different resource
// profiles. Discovery waits on pagination, fetch on the network while holding
// bytes on disk, analysis on CPU, publishing on the sink. Sharing one bound
// across all four means choosing for the worst case.
//
// The channels are bounded deliberately. A full channel is what makes a slow
// stage push back on a fast one, which is why the byte budget in fetch ends up
// governing the whole pipeline: when everything downstream stalls, fetch stops
// being admitted, and discovery blocks behind it.
type Pipeline struct {
	cfg     *config.Config
	fetcher ObjectOpener
	engine  *scanner.Engine
	rep     reporter.Reporter
	gdb     *gorm.DB
	m       *metrics.Metrics

	fetchLimiter   *ByteLimiter
	analyzeLimiter *FixedLimiter
	workDir        string
}

// New builds a pipeline and its limiters.
func New(
	cfg *config.Config,
	fetcher ObjectOpener,
	engine *scanner.Engine,
	rep reporter.Reporter,
	gdb *gorm.DB,
	m *metrics.Metrics,
	workDir string,
) *Pipeline {
	cpu := cfg.AnalyzeCPULimit
	if cpu <= 0 {
		// For CPU-bound work there is no better number than the number of cores
		// available: past that, extra goroutines add context switching and no
		// throughput.
		cpu = runtime.GOMAXPROCS(0)
	}

	p := &Pipeline{
		cfg: cfg, fetcher: fetcher, engine: engine, rep: rep, gdb: gdb, m: m,
		workDir:        workDir,
		fetchLimiter:   NewByteLimiter(stageFetch, cfg.FetchByteBudget, cfg.FetchMaxConns),
		analyzeLimiter: NewFixedLimiter(stageAnalyze, cpu),
	}

	m.WatchLimiter(p.fetchLimiter)
	m.WatchLimiter(p.analyzeLimiter)

	log.Printf("pipeline: fetch budget %d bytes over %d conns, analyze %d workers, publish batch %d / %s",
		cfg.FetchByteBudget, cfg.FetchMaxConns, cpu, cfg.PublishBatchSize, cfg.PublishFlushInterval)
	return p
}

// Run pushes every object through the pipeline and returns once the last
// document has been published.
func (p *Pipeline) Run(ctx context.Context, objects []s3fetcher.S3Object) error {
	jobs := make(chan job, p.cfg.StageQueueSize)
	inputs := make(chan *scanner.ScanInput, p.cfg.StageQueueSize)
	results := make(chan *scanner.FileResult, p.cfg.StageQueueSize)

	stopSampling := p.sampleQueueDepth(map[string]func() int{
		stageFetch:   func() int { return len(jobs) },
		stageAnalyze: func() int { return len(inputs) },
		stagePublish: func() int { return len(results) },
	})
	defer stopSampling()

	var fetchWG, analyzeWG, publishWG sync.WaitGroup

	// Fetch: one goroutine per connection slot; the byte budget decides how many
	// of them may hold data at once.
	for i := 0; i < p.cfg.FetchMaxConns; i++ {
		fetchWG.Add(1)
		go func() {
			defer fetchWG.Done()
			p.runFetch(ctx, jobs, inputs)
		}()
	}

	// Analyze: one goroutine per core.
	for i := 0; i < int(p.analyzeLimiter.Limit()); i++ {
		analyzeWG.Add(1)
		go func() {
			defer analyzeWG.Done()
			p.runAnalyze(ctx, inputs, results)
		}()
	}

	// Publish: exactly one goroutine. Batching needs a single owner of the
	// buffer, and it also removes the old bug where every worker appended to the
	// same JSON file without a lock.
	publishWG.Add(1)
	go func() {
		defer publishWG.Done()
		p.runPublish(ctx, results)
	}()

	err := p.runDiscover(ctx, objects, jobs)

	// Close in order, waiting each time: a stage may only stop once nothing can
	// still arrive for it.
	close(jobs)
	fetchWG.Wait()
	close(inputs)
	analyzeWG.Wait()
	close(results)
	publishWG.Wait()

	return err
}

// runDiscover filters objects and feeds the pipeline.
//
// Dedup is one batched query rather than one per object: discovery holds whole
// pages, so a thousand objects cost one round trip instead of a thousand.
func (p *Pipeline) runDiscover(ctx context.Context, objects []s3fetcher.S3Object, out chan<- job) error {
	started := time.Now()

	ids := make([]string, len(objects))
	for i, obj := range objects {
		ids[i] = hashing.FileID(obj.Bucket, obj.Key, obj.ETag)
	}
	seen, err := db.SeenFileIDs(p.gdb, ids)
	if err != nil {
		p.m.ObserveStage(stageDiscover, started, err)
		return err
	}

	queued := 0
	for i, obj := range objects {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if seen[ids[i]] {
			p.m.ObjectsSkipped.WithLabelValues("already_scanned").Inc()
			continue
		}
		if p.cfg.MaxObjectSize > 0 && obj.Size > p.cfg.MaxObjectSize {
			log.Printf("discover: skipping %s, %d bytes exceeds MAX_OBJECT_SIZE", obj.Key, obj.Size)
			p.m.ObjectsSkipped.WithLabelValues("too_large").Inc()
			continue
		}

		select {
		case out <- job{obj: obj, fileID: ids[i]}:
			queued++
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	p.m.ObserveStage(stageDiscover, started, nil)
	log.Printf("discover: %d queued, %d skipped", queued, len(objects)-queued)
	return nil
}

// runFetch downloads objects, hashing them on the way through.
func (p *Pipeline) runFetch(ctx context.Context, in <-chan job, out chan<- *scanner.ScanInput) {
	for j := range in {
		select {
		case <-ctx.Done():
			return
		default:
		}

		started := time.Now()
		input, err := p.fetchOne(ctx, j)
		p.m.ObserveStage(stageFetch, started, err)
		if err != nil {
			log.Printf("fetch %s: %v", j.obj.Key, err)
			continue
		}

		select {
		case out <- input:
		case <-ctx.Done():
			os.Remove(input.LocalPath)
			return
		}
	}
}

// fetchOne reserves budget for the object, streams it to disk and hashes it in
// the same pass.
func (p *Pipeline) fetchOne(ctx context.Context, j job) (*scanner.ScanInput, error) {
	// The object's size is the weight: this is the point at which memory is
	// actually bounded.
	release, err := p.fetchLimiter.Acquire(ctx, j.obj.Size)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	var body io.ReadCloser

	// Everything the budget is meant to cover has to be finished before it is
	// handed back. Releasing while the response body is still open would leave
	// its network buffers outside the accounting, so the real peak could exceed
	// the budget even though the limiter was obeyed — which is precisely what
	// TestByteBudgetBoundsBytesInFlight caught.
	done := func(err error) {
		if body != nil {
			body.Close()
		}
		release(Outcome{Err: err, Latency: time.Since(start)})
	}

	body, err = p.fetcher.Open(ctx, j.obj.Key)
	if err != nil {
		done(err)
		return nil, err
	}

	// The temp file is named by FileID, so two objects sharing a basename can no
	// longer overwrite each other.
	localPath := filepath.Join(p.workDir, j.fileID)
	f, err := os.Create(localPath)
	if err != nil {
		done(err)
		return nil, err
	}

	h := hashing.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), body)
	if closeErr := f.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		os.Remove(localPath)
		done(copyErr)
		return nil, copyErr
	}

	// Released here rather than after analysis: the budget bounds bytes in
	// flight through the transfer. Holding it across scanning would tie two
	// unrelated resources together and starve fetch behind CPU work.
	done(nil)

	return &scanner.ScanInput{
		FileID:    j.fileID,
		Bucket:    j.obj.Bucket,
		Key:       j.obj.Key,
		Version:   j.obj.ETag,
		Size:      h.Size(),
		Hashes:    h.Sum(),
		LocalPath: localPath,
	}, nil
}

// runAnalyze runs the scanners and deletes the payload once they are done.
func (p *Pipeline) runAnalyze(ctx context.Context, in <-chan *scanner.ScanInput, out chan<- *scanner.FileResult) {
	for input := range in {
		select {
		case <-ctx.Done():
			os.Remove(input.LocalPath)
			return
		default:
		}

		started := time.Now()
		release, err := p.analyzeLimiter.Acquire(ctx, 1)
		if err != nil {
			os.Remove(input.LocalPath)
			return
		}
		result := p.engine.ProcessFile(ctx, input)
		release(Outcome{Latency: time.Since(started)})

		// The payload has no reader left: every scanner needing it has run.
		os.Remove(input.LocalPath)
		p.m.ObserveStage(stageAnalyze, started, err)

		for name, res := range result.Results {
			p.m.Findings.WithLabelValues(name, string(res.Severity)).Inc()
		}

		select {
		case out <- result:
		case <-ctx.Done():
			return
		}
	}
}

// runPublish batches results and flushes them to the sink.
//
// Three triggers, whichever fires first: the batch fills, it grows past a byte
// ceiling, or the interval elapses. The timer starts when the first document
// enters an empty batch rather than ticking on a fixed schedule, which is what
// makes the latency bound a guarantee: no document waits longer than one
// interval. A fixed ticker would publish a document arriving just before a tick
// almost immediately and make one arriving just after wait a whole period.
func (p *Pipeline) runPublish(ctx context.Context, in <-chan *scanner.FileResult) {
	var (
		batch      []*scanner.FileResult
		batchBytes int64
		timer      *time.Timer
		timeout    <-chan time.Time
	)

	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer, timeout = nil, nil
		}
	}
	defer stopTimer()

	for {
		select {
		case result, ok := <-in:
			if !ok {
				// Drain before exiting. Without this, a shutdown discards up to a
				// full batch of findings that were already paid for.
				if len(batch) > 0 {
					p.flush(ctx, batch, "shutdown")
				}
				return
			}

			batch = append(batch, result)
			batchBytes += estimateSize(result)

			if len(batch) == 1 {
				timer = time.NewTimer(p.cfg.PublishFlushInterval)
				timeout = timer.C
			}

			trigger := ""
			switch {
			case len(batch) >= p.cfg.PublishBatchSize:
				trigger = "size"
			case batchBytes >= p.cfg.PublishMaxBytes:
				trigger = "bytes"
			}
			if trigger != "" {
				stopTimer()
				p.flush(ctx, batch, trigger)
				batch, batchBytes = nil, 0
			}

		case <-timeout:
			stopTimer()
			if len(batch) > 0 {
				p.flush(ctx, batch, "interval")
				batch, batchBytes = nil, 0
			}

		case <-ctx.Done():
			// Still flush: these results are finished work, and the context being
			// cancelled is not a reason to throw them away.
			if len(batch) > 0 {
				p.flush(context.WithoutCancel(ctx), batch, "cancelled")
			}
			return
		}
	}
}

// flush writes one batch to the sink and only then records the objects as scanned.
//
// The ordering is load-bearing. Marking them first and publishing second would
// mean a crash in between loses those findings permanently: the records say the
// objects were scanned, so they are never queued again.
func (p *Pipeline) flush(ctx context.Context, batch []*scanner.FileResult, trigger string) {
	started := time.Now()

	err := p.send(ctx, batch)
	p.m.PublishFlush.WithLabelValues(trigger).Inc()
	p.m.PublishBatchLen.WithLabelValues(trigger).Observe(float64(len(batch)))
	p.m.ObserveStage(stagePublish, started, err)

	if err != nil {
		// Leave the records unwritten so the objects are rescanned next run.
		log.Printf("publish: %d results lost: %v", len(batch), err)
		return
	}

	for _, r := range batch {
		rec := &db.FileRecord{
			FileID: r.FileID, Bucket: r.Bucket, ObjectKey: r.Key,
			Version: r.Version, Size: r.Size,
			MD5: r.Hashes["md5"], SHA1: r.Hashes["sha1"], SHA256: r.Hashes["sha256"],
			FetchedAt: r.ScanTime,
		}
		if err := db.UpsertFileRecord(p.gdb, rec); err != nil {
			log.Printf("publish: recording %s: %v", r.Key, err)
		}
	}
}

// send prefers the sink's batch API and falls back to one call per document.
func (p *Pipeline) send(ctx context.Context, batch []*scanner.FileResult) error {
	if br, ok := p.rep.(reporter.BatchReporter); ok {
		return br.ReportBatch(ctx, batch)
	}
	for _, r := range batch {
		if err := p.rep.Report(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// estimateSize approximates a document's serialised size, so the byte ceiling
// can be enforced without marshalling twice.
func estimateSize(r *scanner.FileResult) int64 {
	const envelope = 512
	size := int64(envelope + len(r.Bucket) + len(r.Key))
	for name, res := range r.Results {
		size += int64(len(name) + 64 + len(res.Detail)*64)
	}
	return size
}

// sampleQueueDepth publishes channel occupancy until the returned function is
// called. Sampled rather than updated at every send, which would put a metric
// write on the hot path of every item.
func (p *Pipeline) sampleQueueDepth(depths map[string]func() int) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for stage, depth := range depths {
					p.m.QueueDepth.WithLabelValues(stage).Set(float64(depth()))
				}
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}
