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

// scanJob carries an input together with the byte budget it still holds.
//
// The release travels with the payload because whoever deletes the temp file is
// the only one who can honestly say the bytes are gone — and that is the analyze
// stage, not fetch.
type scanJob struct {
	in      *scanner.ScanInput
	release func(Outcome)
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

	// byteLimiter is the global brake. It is held from the moment a transfer
	// starts until the payload is deleted after scanning, because the bytes are
	// resident for that whole span — first in network buffers, then on disk.
	// Releasing it when the transfer ended, as an earlier version did, meant
	// fetch never backed off: it filled the channel and the disk while the
	// accounting claimed the budget was free.
	byteLimiter *ByteLimiter
	// connLimiter bounds concurrent transfers, a shorter span and a different
	// resource.
	connLimiter    *FixedLimiter
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
		byteLimiter:    NewByteLimiter("bytes", cfg.FetchByteBudget),
		connLimiter:    NewFixedLimiter("conns", cfg.FetchMaxConns),
		analyzeLimiter: NewFixedLimiter(stageAnalyze, cpu),
	}

	m.WatchLimiter(p.byteLimiter)
	m.WatchLimiter(p.connLimiter)
	m.WatchLimiter(p.analyzeLimiter)

	log.Printf("pipeline: fetch budget %d bytes over %d conns, analyze %d workers, publish batch %d / %s",
		cfg.FetchByteBudget, cfg.FetchMaxConns, cpu, cfg.PublishBatchSize, cfg.PublishFlushInterval)
	return p
}

// Run pushes every object through the pipeline and returns once the last
// document has been published.
func (p *Pipeline) Run(ctx context.Context, objects []s3fetcher.S3Object) error {
	jobs := make(chan job, p.cfg.StageQueueSize)
	inputs := make(chan *scanJob, p.cfg.StageQueueSize)
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

	err := p.runDiscover(ctx, objects, jobs, results)

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
func (p *Pipeline) runDiscover(ctx context.Context, objects []s3fetcher.S3Object, out chan<- job, notices chan<- *scanner.FileResult) error {
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

			// Not scanning something is itself worth reporting. The largest
			// objects in a bucket are exactly where something would be hidden,
			// and a log line plus a counter disappears the moment the pod does.
			// Publishing the gap puts it in the same index as real findings, so
			// the alerting that already watches that index catches it too.
			select {
			case notices <- coverageGap(obj, ids[i], "exceeds_max_object_size", p.cfg.MaxObjectSize):
			case <-ctx.Done():
				return ctx.Err()
			}
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

// coverageGap builds a document recording that an object was deliberately not
// scanned.
//
// Match is false because nothing was detected — nothing was looked at. The gap
// is carried by scanned:false in the detail instead, so a dashboard can ask for
// coverage holes separately from detections.
//
// Deliberately no FileRecord is written for these. Leaving the object unrecorded
// means raising MAX_OBJECT_SIZE later picks it up on the next run rather than
// skipping it forever as "already handled". Republishing the same notice each
// run is harmless where the sink keys on a deterministic document id.
func coverageGap(obj s3fetcher.S3Object, fileID, reason string, limit int64) *scanner.FileResult {
	return &scanner.FileResult{
		FileID:  fileID,
		Bucket:  obj.Bucket,
		Key:     obj.Key,
		Version: obj.ETag,
		Size:    obj.Size,
		Hashes:  map[string]string{}, // never fetched, so nothing was hashed
		Results: map[string]scanner.Result{
			"size_gate": {
				Match:    false,
				Severity: scanner.SeverityLow,
				Detail: map[string]any{
					"scanned":     false,
					"reason":      reason,
					"object_size": obj.Size,
					"limit":       limit,
				},
			},
		},
		ScanTime: time.Now().UTC(),
	}
}

// runFetch downloads objects, hashing them on the way through.
func (p *Pipeline) runFetch(ctx context.Context, in <-chan job, out chan<- *scanJob) {
	for j := range in {
		select {
		case <-ctx.Done():
			return
		default:
		}

		started := time.Now()
		sj, err := p.fetchOne(ctx, j)
		p.m.ObserveStage(stageFetch, started, err)
		if err != nil {
			log.Printf("fetch %s: %v", j.obj.Key, err)
			continue
		}

		select {
		case out <- sj:
		case <-ctx.Done():
			// Blocking here while holding the budget is the backpressure
			// working. On the way out it still has to be handed back.
			os.Remove(sj.in.LocalPath)
			sj.release(Outcome{Err: ctx.Err()})
			return
		}
	}
}

// fetchOne reserves budget for the object, streams it to disk and hashes it in
// the same pass.
func (p *Pipeline) fetchOne(ctx context.Context, j job) (*scanJob, error) {
	// The object's size is the weight. This reservation outlives the function:
	// it travels to the analyze stage and is released once the payload is gone.
	releaseBytes, err := p.byteLimiter.Acquire(ctx, j.obj.Size)
	if err != nil {
		return nil, err
	}

	// A connection slot, by contrast, is only needed while bytes are moving.
	releaseConn, err := p.connLimiter.Acquire(ctx, 1)
	if err != nil {
		releaseBytes(Outcome{Err: err})
		return nil, err
	}

	start := time.Now()
	var body io.ReadCloser

	// Anything the transfer holds must be finished before the connection slot
	// goes back. Releasing while the response body is still open would leave its
	// network buffers outside the accounting, so the real peak could exceed the
	// budget even though the limiter was obeyed.
	endTransfer := func(err error) {
		if body != nil {
			body.Close()
		}
		releaseConn(Outcome{Err: err, Latency: time.Since(start)})
	}
	// fail hands everything back, for the paths that produce no payload.
	fail := func(err error) (*scanJob, error) {
		endTransfer(err)
		releaseBytes(Outcome{Err: err})
		return nil, err
	}

	body, err = p.fetcher.Open(ctx, j.obj.Key)
	if err != nil {
		return fail(err)
	}

	// The temp file is named by FileID, so two objects sharing a basename can no
	// longer overwrite each other.
	localPath := filepath.Join(p.workDir, j.fileID)
	f, err := os.Create(localPath)
	if err != nil {
		return fail(err)
	}

	h := hashing.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), body)
	if closeErr := f.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		os.Remove(localPath)
		return fail(copyErr)
	}

	endTransfer(nil)

	return &scanJob{
		in: &scanner.ScanInput{
			FileID:    j.fileID,
			Bucket:    j.obj.Bucket,
			Key:       j.obj.Key,
			Version:   j.obj.ETag,
			Size:      h.Size(),
			Hashes:    h.Sum(),
			LocalPath: localPath,
		},
		release: releaseBytes,
	}, nil
}

// runAnalyze runs the scanners, deletes the payload, and only then returns the
// byte budget the fetch stage reserved for it.
func (p *Pipeline) runAnalyze(ctx context.Context, in <-chan *scanJob, out chan<- *scanner.FileResult) {
	for sj := range in {
		// Whatever happens, the payload is deleted and the budget handed back.
		// Missing either on any path leaks disk or wedges the pipeline: once the
		// budget is held by reservations nobody returns, fetch never gets
		// another token.
		done := func() {
			os.Remove(sj.in.LocalPath)
			sj.release(Outcome{})
		}

		select {
		case <-ctx.Done():
			done()
			return
		default:
		}

		started := time.Now()
		releaseCPU, err := p.analyzeLimiter.Acquire(ctx, 1)
		if err != nil {
			done()
			return
		}
		result := p.engine.ProcessFile(ctx, sj.in)
		releaseCPU(Outcome{Latency: time.Since(started)})

		// Every scanner that needed the bytes has run, so the payload can go —
		// and only now may the budget be returned.
		done()
		p.m.ObserveStage(stageAnalyze, started, nil)

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

			size := estimateSize(result)

			// A document that exceeds the ceiling on its own goes alone.
			//
			// Appending it first would drag whatever had already accumulated
			// into the same request, pushing it further past the limit rather
			// than closer to it — and Elasticsearch rejects a _bulk body over
			// http.max_content_length outright rather than splitting it.
			if size >= p.cfg.PublishMaxBytes {
				stopTimer()
				if len(batch) > 0 {
					p.flush(ctx, batch, "bytes")
					batch, batchBytes = nil, 0
				}
				p.flush(ctx, []*scanner.FileResult{result}, "oversize")
				continue
			}

			batch = append(batch, result)
			batchBytes += size

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
