package pipeline

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/hashing"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/scanner"
	"github.com/luhtaf/s3nitor/internal/source"
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

// Summary is what one run did, logged at exit so a benchmark harness can read
// it back without scraping a metrics endpoint that dies with the process.
type Summary struct {
	Listed   int
	Scanned  int
	Skipped  int
	Failed   int
	Spilled  int
	Duration time.Duration
}

// job carries an object from discovery to fetch.
type job struct {
	ref    source.ObjectRef
	fileID string
}

// Pipeline runs the scan as stages connected by bounded channels.
//
//	discover ─► fetch+hash ─► dispatch ─┬─► ioc ────────┐
//	                                    ├─► yara ───────┼─► publish
//	                                    └─► virustotal ─┘
//
// The boundaries follow one rule: a stage exists to separate different resource
// profiles. Discovery waits on pagination, fetch on the network while holding
// bytes, the local scanners on CPU, the intel scanners on somebody else's quota.
// Sharing one bound across all of them means choosing for the worst case.
//
// The channels are bounded deliberately: a full channel is what makes a slow
// stage push back on a fast one.
type Pipeline struct {
	cfg     *config.Config
	fetcher ObjectOpener
	engine  *scanner.Engine
	rep     reporter.Reporter
	gdb     *gorm.DB
	m       *metrics.Metrics

	listed  atomic.Int64
	scanned atomic.Int64
	skipped atomic.Int64
	failed  atomic.Int64
	spilled atomic.Int64

	// byteLimiter is the global brake. It is held from the moment a transfer
	// starts until the payload is deleted after scanning, because the bytes are
	// resident for that whole span — first in network buffers, then on disk.
	byteLimiter *ByteLimiter
	// connLimiter bounds concurrent transfers, a shorter span and a different
	// resource.
	connLimiter *FixedLimiter
	// cpuLimiter is shared by every local scanner lane. One limiter rather than
	// one per lane: separate GOMAXPROCS budgets would permit a multiple of the
	// intended parallelism.
	cpuLimiter *FixedLimiter

	lanes   map[string]*lane
	workDir string
}

// New builds a pipeline, its limiters and one lane per enabled scanner.
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
		// For CPU-bound work there is no better number than the cores available:
		// past that, extra goroutines add context switching and no throughput.
		cpu = runtime.GOMAXPROCS(0)
	}

	p := &Pipeline{
		cfg: cfg, fetcher: fetcher, engine: engine, rep: rep, gdb: gdb, m: m,
		workDir:     workDir,
		byteLimiter: NewByteLimiter("bytes", cfg.FetchByteBudget),
		connLimiter: NewFixedLimiter("conns", cfg.FetchMaxConns),
		cpuLimiter:  NewFixedLimiter("cpu", cpu),
	}

	m.WatchLimiter(p.byteLimiter)
	m.WatchLimiter(p.connLimiter)
	m.WatchLimiter(p.cpuLimiter)

	p.lanes = buildLanes(cfg, engine.Scanners(), p.cpuLimiter, m)

	log.Printf("pipeline: byte budget %d over %d conns, cpu %d, %d lanes, publish batch %d / %s",
		cfg.FetchByteBudget, cfg.FetchMaxConns, cpu, len(p.lanes),
		cfg.PublishBatchSize, cfg.PublishFlushInterval)
	return p
}

// Run pushes every object through the pipeline and returns once the last
// finding has been published.
func (p *Pipeline) Run(ctx context.Context, refs <-chan source.ObjectRef) (Summary, error) {
	started := time.Now()

	jobs := make(chan job, p.cfg.StageQueueSize)
	payloads := make(chan *payload, p.cfg.StageQueueSize)
	findings := make(chan *scanner.Finding, p.cfg.StageQueueSize)

	stopSampling := p.sampleQueueDepth(map[string]func() int{
		stageFetch:   func() int { return len(jobs) },
		stageAnalyze: func() int { return len(payloads) },
		stagePublish: func() int { return len(findings) },
	})
	defer stopSampling()

	var fetchWG, dispatchWG, laneWG, publishWG sync.WaitGroup

	for i := 0; i < p.cfg.FetchMaxConns; i++ {
		fetchWG.Add(1)
		go func() {
			defer fetchWG.Done()
			p.runFetch(ctx, jobs, payloads)
		}()
	}

	// A single dispatcher: fanning one payload out to every lane is bookkeeping,
	// not work, and one owner makes the reference counting easy to follow.
	dispatchWG.Add(1)
	go func() {
		defer dispatchWG.Done()
		p.runDispatch(ctx, payloads, findings)
	}()

	for _, l := range p.lanes {
		for i := 0; i < l.workers; i++ {
			laneWG.Add(1)
			go func(l *lane) {
				defer laneWG.Done()
				p.runLane(ctx, l, findings)
			}(l)
		}
	}

	// Exactly one publisher. Batching needs a single owner of the buffer, and it
	// also removes by construction the old bug where every worker appended to
	// the same file without a lock.
	publishWG.Add(1)
	go func() {
		defer publishWG.Done()
		p.runPublish(ctx, findings)
	}()

	err := p.runDiscover(ctx, refs, jobs, findings)

	// Closed in order, waiting each time: a stage may only stop once nothing can
	// still arrive for it.
	close(jobs)
	fetchWG.Wait()
	close(payloads)
	dispatchWG.Wait()
	for _, l := range p.lanes {
		close(l.in)
	}
	laneWG.Wait()
	close(findings)
	publishWG.Wait()

	return Summary{
		Listed:   int(p.listed.Load()),
		Scanned:  int(p.scanned.Load()),
		Skipped:  int(p.skipped.Load()),
		Failed:   int(p.failed.Load()),
		Spilled:  int(p.spilled.Load()),
		Duration: time.Since(started),
	}, err
}

// runDiscover filters objects and feeds the pipeline.
//
// Consumes a stream rather than a slice. The previous version pulled every
// object's metadata into memory before a single worker started, so memory scaled
// with the object count ahead of any work being done — and an event source never
// ends, so there is no slice to take.
//
// Dedup is batched: references are accumulated up to dedupBatch and answered in
// one query. One query per object turned a thousand objects into a thousand
// round trips.
func (p *Pipeline) runDiscover(ctx context.Context, refs <-chan source.ObjectRef, out chan<- job, notices chan<- *scanner.Finding) error {
	const dedupBatch = 500

	batch := make([]source.ObjectRef, 0, dedupBatch)

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		defer func() { batch = batch[:0] }()

		ids := make([]string, len(batch))
		for i, ref := range batch {
			ids[i] = hashing.FileID(ref.Bucket, ref.Key, ref.Version)
		}
		seen, err := db.SeenFileIDs(p.gdb, ids)
		if err != nil {
			return err
		}

		for i, ref := range batch {
			if seen[ids[i]] {
				p.m.ObjectsSkipped.WithLabelValues("already_scanned").Inc()
				p.skipped.Add(1)
				continue
			}
			if p.cfg.MaxObjectSize > 0 && ref.Size > p.cfg.MaxObjectSize {
				log.Printf("discover: skipping %s, %d bytes exceeds MAX_OBJECT_SIZE", ref.Key, ref.Size)
				p.m.ObjectsSkipped.WithLabelValues("too_large").Inc()
				p.skipped.Add(1)

				// Not scanning something is itself worth reporting: the largest
				// objects are exactly where something would be hidden, and a log
				// line plus a counter disappears with the pod.
				select {
				case notices <- coverageGap(ref, ids[i], "exceeds_max_object_size", p.cfg.MaxObjectSize):
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}

			select {
			case out <- job{ref: ref, fileID: ids[i]}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}

	started := time.Now()
	for ref := range refs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		p.listed.Add(1)
		batch = append(batch, ref)
		if len(batch) >= dedupBatch {
			if err := flush(); err != nil {
				p.m.ObserveStage(stageDiscover, started, err)
				return err
			}
		}
	}

	err := flush()
	p.m.ObserveStage(stageDiscover, started, err)
	log.Printf("discover: %d seen, %d skipped", p.listed.Load(), p.skipped.Load())
	return err
}

// coverageGap records that an object was deliberately not scanned.
//
// Match is false because nothing was detected — nothing was looked at. The gap
// is carried by scanned:false in the detail instead, so a dashboard can ask for
// coverage holes separately from detections.
//
// No FileRecord is written for these on purpose: leaving the object unrecorded
// means raising MAX_OBJECT_SIZE later picks it up on the next run rather than
// skipping it forever as already handled.
func coverageGap(ref source.ObjectRef, fileID, reason string, limit int64) *scanner.Finding {
	return &scanner.Finding{
		FileID:   fileID,
		Bucket:   ref.Bucket,
		Key:      ref.Key,
		Version:  ref.Version,
		Size:     ref.Size,
		Scanner:  "size_gate",
		Match:    false,
		Severity: scanner.SeverityLow,
		Detail: map[string]any{
			"scanned":     false,
			"reason":      reason,
			"object_size": ref.Size,
			"limit":       limit,
		},
		ScannedAt: time.Now().UTC(),
	}
}

// payload is a fetched object plus the resources it is holding.
//
// Several scanners run over the same file, so neither the temp file nor the byte
// budget can be released by whichever finishes first. refs counts the scanners
// that actually read the bytes; the last one out deletes the file and hands the
// budget back.
type payload struct {
	in      *scanner.ScanInput
	refs    atomic.Int32
	release func(Outcome)
	once    sync.Once
}

// done marks one payload-reading scanner as finished with the file.
//
// Called on every exit path, including spills and cancellation. Missing one
// leaks a temp file and, worse, leaks byte budget: a budget held by reservations
// nobody returns never issues another token, and fetch stops for good.
func (p *payload) done() {
	if p.refs.Add(-1) <= 0 {
		p.free()
	}
}

func (p *payload) free() {
	p.once.Do(func() {
		if p.in.LocalPath != "" {
			os.Remove(p.in.LocalPath)
		}
		p.release(Outcome{})
	})
}

// task is one unit of scanning work: a single scanner against a single object.
//
// This is the unit the whole redesign converges on. A file is never simply
// "scanned" when an IOC lookup returns in microseconds and a VirusTotal query
// waits hours behind a quota, so the schedulable thing is the pair.
type task struct {
	payload *payload
	scanner scanner.Scanner
}

// fullPolicy decides what happens when a lane's queue is full.
type fullPolicy int

const (
	// policyBlock pushes back on the stage upstream. Correct when the wait is
	// short — CPU saturation clears in seconds, and slowing intake is honest.
	policyBlock fullPolicy = iota
	// policySpill writes the task to the pending store and moves on. Correct
	// when the wait is unbounded: blocking on an API quota lets a third party
	// set the throughput of the entire pipeline.
	policySpill
)

// lane is one scanner's queue, limiter and full-queue policy.
type lane struct {
	scanner scanner.Scanner
	in      chan *task
	limiter Limiter
	policy  fullPolicy
	workers int
}

// buildLanes gives each scanner its own queue and the limiter that matches what
// it actually waits on.
//
// Local scanners share one CPU limiter rather than getting one each: two lanes
// with GOMAXPROCS apiece would permit twice the intended parallelism, which is
// how a CPU bound quietly stops being a bound.
func buildLanes(cfg *config.Config, scanners []scanner.Scanner, cpu Limiter, m *metrics.Metrics) map[string]*lane {
	spills := make(map[string]bool, len(cfg.SpillScanners))
	for _, name := range cfg.SpillScanners {
		spills[name] = true
	}

	lanes := make(map[string]*lane, len(scanners))
	for _, sc := range scanners {
		if !sc.Enabled() {
			continue
		}

		l := &lane{
			scanner: sc,
			in:      make(chan *task, cfg.StageQueueSize),
			limiter: cpu,
			policy:  policyBlock,
			workers: int(cpu.Limit()),
		}

		if spills[sc.Name()] {
			perMin := cfg.ScannerRatePerMin[sc.Name()]
			if perMin <= 0 {
				perMin = 60
			}
			l.limiter = NewRateLimiter(sc.Name(), perMin/60)
			l.policy = policySpill
			// One worker is enough: the rate limiter, not the worker count,
			// decides how fast this lane moves.
			l.workers = 1
			m.WatchLimiter(l.limiter)
		}

		lanes[sc.Name()] = l
		log.Printf("lane %s: limiter=%s policy=%s workers=%d",
			sc.Name(), l.limiter.Name(), policyName(l.policy), l.workers)
	}
	return lanes
}

func policyName(p fullPolicy) string {
	if p == policySpill {
		return "spill"
	}
	return "block"
}

// runFetch downloads objects, hashing them on the way through.
func (p *Pipeline) runFetch(ctx context.Context, in <-chan job, out chan<- *payload) {
	for j := range in {
		select {
		case <-ctx.Done():
			return
		default:
		}

		started := time.Now()
		pl, err := p.fetchOne(ctx, j)
		p.m.ObserveStage(stageFetch, started, err)
		if err != nil {
			log.Printf("fetch %s: %v", j.ref.Key, err)
			p.failed.Add(1)
			continue
		}

		select {
		case out <- pl:
		case <-ctx.Done():
			// Blocking here while holding the budget is the backpressure
			// working. On the way out it still has to be handed back.
			pl.free()
			return
		}
	}
}

// fetchOne reserves budget for the object, streams it to disk and hashes it in
// the same pass.
func (p *Pipeline) fetchOne(ctx context.Context, j job) (*payload, error) {
	// The object's size is the weight. This reservation outlives the function:
	// it travels with the payload and is released once the file is gone.
	releaseBytes, err := p.byteLimiter.Acquire(ctx, j.ref.Size)
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
	fail := func(err error) (*payload, error) {
		endTransfer(err)
		releaseBytes(Outcome{Err: err})
		return nil, err
	}

	body, err = p.fetcher.Open(ctx, j.ref.Key)
	if err != nil {
		return fail(err)
	}

	// Named by FileID, so two objects sharing a basename cannot overwrite each
	// other.
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

	return &payload{
		in: &scanner.ScanInput{
			FileID:    j.fileID,
			Bucket:    j.ref.Bucket,
			Key:       j.ref.Key,
			Version:   j.ref.Version,
			Size:      h.Size(),
			Hashes:    h.Sum(),
			LocalPath: localPath,
		},
		release: releaseBytes,
	}, nil
}

// runDispatch fans one payload out to one task per enabled scanner.
func (p *Pipeline) runDispatch(ctx context.Context, in <-chan *payload, findings chan<- *scanner.Finding) {
	for pl := range in {
		// Only the scanners that read the file hold a reference to it. IOC and
		// the intel lookups need nothing but the hashes, so they must not keep
		// a large temp file alive — nor delay the byte budget going back.
		readers := int32(0)
		for _, l := range p.lanes {
			if l.scanner.NeedsPayload() {
				readers++
			}
		}
		if readers == 0 {
			// Nothing will read the bytes, so free them now rather than at the
			// end of scanning.
			pl.free()
		}
		pl.refs.Store(readers)

		for _, l := range p.lanes {
			t := &task{payload: pl, scanner: l.scanner}

			if l.policy == policySpill {
				select {
				case l.in <- t:
				default:
					// Queue full and the wait is unbounded: park it durably and
					// keep the pipeline moving.
					p.spill(ctx, t, findings)
				}
				continue
			}

			select {
			case l.in <- t:
			case <-ctx.Done():
				if l.scanner.NeedsPayload() {
					pl.done()
				}
				return
			}
		}
	}
}

// spill parks a task in the pending store for a later run.
func (p *Pipeline) spill(ctx context.Context, t *task, findings chan<- *scanner.Finding) {
	in := t.payload.in
	if err := db.EnqueuePending(p.gdb, in.FileID, t.scanner.Name(), t.scanner.RulesVersion(), p.cfg.PendingRetryBase); err != nil {
		log.Printf("spill %s/%s: %v", in.Key, t.scanner.Name(), err)
	}
	p.spilled.Add(1)
	p.m.ObjectsSkipped.WithLabelValues("spilled_" + t.scanner.Name()).Inc()

	// A spilled task that needs the bytes will re-download them on retry;
	// holding disk for hours waiting on a quota is not an option.
	if t.scanner.NeedsPayload() {
		t.payload.done()
	}
}

// runLane processes one scanner's queue.
func (p *Pipeline) runLane(ctx context.Context, l *lane, findings chan<- *scanner.Finding) {
	for t := range l.in {
		func() {
			// The reference is given up however this task ends.
			defer func() {
				if l.scanner.NeedsPayload() {
					t.payload.done()
				}
			}()

			select {
			case <-ctx.Done():
				return
			default:
			}

			started := time.Now()
			release, err := l.limiter.Acquire(ctx, 1)
			if err != nil {
				// Cancelled or rate-limited out: park it rather than drop it.
				if l.policy == policySpill {
					if e := db.EnqueuePending(p.gdb, t.payload.in.FileID, l.scanner.Name(),
						l.scanner.RulesVersion(), p.cfg.PendingRetryBase); e != nil {
						log.Printf("lane %s: %v", l.scanner.Name(), e)
					}
				}
				return
			}

			finding := scanner.ScanOne(ctx, l.scanner, t.payload.in)
			release(Outcome{Latency: time.Since(started)})

			p.m.ObserveStage(stageAnalyze, started, nil)
			p.m.Findings.WithLabelValues(finding.Scanner, string(finding.Severity)).Inc()
			p.scanned.Add(1)

			select {
			case findings <- finding:
			case <-ctx.Done():
			}
		}()
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
func (p *Pipeline) runPublish(ctx context.Context, in <-chan *scanner.Finding) {
	var (
		batch      []*scanner.Finding
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
				p.flush(ctx, []*scanner.Finding{result}, "oversize")
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
func (p *Pipeline) flush(ctx context.Context, batch []*scanner.Finding, trigger string) {
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

	// One record per object, not per finding. Several findings share a FileID —
	// one per scanner — and writing the same row repeatedly is wasted work.
	//
	// A record is written only once every finding for that object in this batch
	// has been accepted by the sink. Marking it earlier would let a crash lose
	// the remaining verdicts permanently: the record says the object was
	// handled, so it is never queued again.
	recorded := make(map[string]bool, len(batch))
	for _, f := range batch {
		if recorded[f.FileID] || f.Scanner == "size_gate" {
			continue
		}
		recorded[f.FileID] = true

		if err := db.UpsertFileRecord(p.gdb, &db.FileRecord{
			FileID: f.FileID, Bucket: f.Bucket, ObjectKey: f.Key,
			Version: f.Version, Size: f.Size,
			MD5: f.Hashes["md5"], SHA1: f.Hashes["sha1"], SHA256: f.Hashes["sha256"],
			FetchedAt: f.ScannedAt,
		}); err != nil {
			log.Printf("publish: recording %s: %v", f.Key, err)
			continue
		}
		// The scanner that produced this finding is done with this object.
		if err := db.MarkDone(p.gdb, f.FileID, f.Scanner); err != nil {
			log.Printf("publish: marking %s/%s done: %v", f.Key, f.Scanner, err)
		}
	}
}

// send prefers the sink's batch API and falls back to one call per document.
func (p *Pipeline) send(ctx context.Context, batch []*scanner.Finding) error {
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
func estimateSize(f *scanner.Finding) int64 {
	// A finding carries identity, hashes and one verdict, so its size is roughly
	// constant regardless of how large the object was. What makes one big is the
	// detail payload — a file tripping hundreds of YARA rules.
	const envelope = 512
	return int64(envelope + len(f.Bucket) + len(f.Key) + len(f.Scanner) + len(f.Detail)*96)
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
