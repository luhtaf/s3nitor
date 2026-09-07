package async

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// Collector polls one scanner's outstanding work.
//
// Keyed by scanner name because a continuation names the scanner that issued
// its token, and only that scanner knows how to read it.
type Collector interface {
	scanner.Resumable
	Name() string
}

// Worker collects verdicts for scans that were handed off.
//
// It has two ways in, and they are not redundant. The Kafka consumer makes
// collection prompt; the sweeper over the ledger makes it certain. A message
// can be lost — a broker outage, a topic retention window that expires while a
// sandbox is still working — and the ledger row is what survives that. Running
// only the consumer would quietly drop those; running only the sweeper would
// work, just at the sweep interval rather than immediately.
type Worker struct {
	gdb        *gorm.DB
	rep        reporter.Reporter
	collectors map[string]Collector
	consumer   *KafkaConsumer

	instance     string
	pollInterval time.Duration
	sweepEvery   time.Duration
	leaseFor     time.Duration
	maxAge       time.Duration
	batch        int
}

type WorkerOptions struct {
	Instance     string
	PollInterval time.Duration
	SweepEvery   time.Duration
	LeaseFor     time.Duration
	MaxAge       time.Duration
	Batch        int
}

func NewWorker(gdb *gorm.DB, rep reporter.Reporter, consumer *KafkaConsumer,
	collectors []Collector, o WorkerOptions) *Worker {

	m := make(map[string]Collector, len(collectors))
	for _, c := range collectors {
		m[c.Name()] = c
	}
	if o.Batch <= 0 {
		o.Batch = 50
	}
	if o.SweepEvery <= 0 {
		o.SweepEvery = time.Minute
	}
	if o.LeaseFor <= 0 {
		// Longer than a poll takes, shorter than an analysis. A lease that
		// outlives the analysis would strand the task if this process died mid
		// poll; one shorter than the poll would let a second worker pick up
		// work still in progress.
		o.LeaseFor = 5 * time.Minute
	}
	return &Worker{
		gdb: gdb, rep: rep, consumer: consumer, collectors: m,
		instance:     o.Instance,
		pollInterval: o.PollInterval,
		sweepEvery:   o.SweepEvery,
		leaseFor:     o.LeaseFor,
		maxAge:       o.MaxAge,
		batch:        o.Batch,
	}
}

// Run blocks until the context ends.
func (w *Worker) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.sweep(ctx)
	}()

	if w.consumer != nil {
		deliveries, err := w.consumer.Consume(ctx)
		if err != nil {
			return err
		}
		for d := range deliveries {
			w.handle(ctx, d.Continuation)
			// Acknowledged whatever the outcome. The ledger is what schedules
			// the next poll, so holding the offset back would only re-deliver a
			// message the ledger already accounts for — and would stall every
			// continuation behind it on the same partition.
			if err := d.Ack(); err != nil {
				log.Printf("async: ack: %v", err)
			}
		}
	}

	<-done
	return ctx.Err()
}

// sweep picks up continuations the broker did not deliver.
func (w *Worker) sweep(ctx context.Context) {
	t := time.NewTicker(w.sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		tasks, err := db.ClaimPending(w.gdb, w.instance, w.leaseFor, w.batch)
		if err != nil {
			log.Printf("async: claim: %v", err)
			continue
		}
		for _, task := range tasks {
			if task.ResumeToken == "" {
				// Not a continuation: work that never started, which belongs to
				// the scanner's own retry path and not here. Put it back rather
				// than holding a lease on it.
				if e := db.RescheduleContinuation(w.gdb, task.FileID, task.Scanner, w.pollInterval); e != nil {
					log.Printf("async: release %s/%s: %v", task.FileID, task.Scanner, e)
				}
				continue
			}
			c, err := w.fromTask(task)
			if err != nil {
				log.Printf("async: rebuilding %s/%s: %v", task.FileID, task.Scanner, err)
				continue
			}
			w.handle(ctx, c)
		}
	}
}

// fromTask rebuilds a continuation from the ledger plus the file record.
func (w *Worker) fromTask(t db.ScanTask) (Continuation, error) {
	rec, err := db.GetFileRecord(w.gdb, t.FileID)
	if err != nil {
		return Continuation{}, fmt.Errorf("file record: %w", err)
	}
	hashes := map[string]string{}
	for k, v := range map[string]string{"md5": rec.MD5, "sha1": rec.SHA1, "sha256": rec.SHA256} {
		if v != "" {
			hashes[k] = v
		}
	}
	return Continuation{
		FileID:       rec.FileID,
		Bucket:       rec.Bucket,
		Key:          rec.ObjectKey,
		Version:      rec.Version,
		Size:         rec.Size,
		Hashes:       hashes,
		Scanner:      t.Scanner,
		RulesVersion: t.RulesVersion,
		Token:        t.ResumeToken,
		SubmittedAt:  t.SubmittedAt,
		PollAfter:    t.NextAttemptAt,
	}, nil
}

// handle advances one continuation by exactly one step.
func (w *Worker) handle(ctx context.Context, c Continuation) {
	col, ok := w.collectors[c.Scanner]
	if !ok {
		// Nothing here can read this token. Rescheduling would spin forever, so
		// the task is failed with a document that says why — silence would read
		// as a clean verdict.
		log.Printf("async: no collector for scanner %q, failing %s", c.Scanner, c.Key)
		w.finish(ctx, c, scanner.Result{}, fmt.Errorf("no collector registered for scanner %q", c.Scanner))
		return
	}

	// Abandon an analysis that never finishes. A sandbox that silently drops a
	// submission would otherwise leave this polling until the heat death of the
	// cluster, publishing nothing — and nothing is indistinguishable from clean.
	if w.maxAge > 0 && !c.SubmittedAt.IsZero() && time.Since(c.SubmittedAt) > w.maxAge {
		log.Printf("async: %s/%s abandoned after %s", c.Key, c.Scanner, time.Since(c.SubmittedAt).Round(time.Second))
		w.finish(ctx, c, scanner.Result{},
			fmt.Errorf("analysis %s did not finish within %s", c.Token, w.maxAge))
		return
	}

	// Too early. Kafka has no delayed delivery, so an early message is put back
	// on the ledger's clock rather than waited on — sleeping here would block
	// every other continuation on this partition behind the slowest analysis.
	if !c.PollAfter.IsZero() && time.Now().Before(c.PollAfter) {
		return
	}

	res, done, err := col.Poll(ctx, c.Token)
	switch {
	case err != nil:
		// A transient failure of the sandbox's API, not of the analysis. Try
		// again on the next tick rather than publishing a verdict we do not have.
		log.Printf("async: poll %s/%s: %v", c.Key, c.Scanner, err)
		w.reschedule(c)
	case !done:
		w.reschedule(c)
	default:
		w.finish(ctx, c, res, nil)
	}
}

func (w *Worker) reschedule(c Continuation) {
	if err := db.RescheduleContinuation(w.gdb, c.FileID, c.Scanner, w.pollInterval); err != nil {
		log.Printf("async: reschedule %s/%s: %v", c.Key, c.Scanner, err)
	}
}

// finish publishes the verdict and closes the ledger row.
//
// Publish first, mark done second — the same ordering the pipeline uses, and for
// the same reason. Reversed, a crash in between loses the verdict permanently:
// the row would claim the scan was handled, so nothing would ever collect it
// again. This way a crash costs a duplicate publish, which is free because
// Finding.DocID is deterministic and the second write overwrites the first.
func (w *Worker) finish(ctx context.Context, c Continuation, res scanner.Result, scanErr error) {
	f := c.Finding(res, scanErr)
	if err := w.rep.Report(ctx, f); err != nil {
		log.Printf("async: publishing %s/%s: %v", c.Key, c.Scanner, err)
		w.reschedule(c)
		return
	}

	if scanErr != nil {
		if err := db.MarkFailed(w.gdb, c.FileID, c.Scanner, scanErr.Error()); err != nil {
			log.Printf("async: marking failed %s/%s: %v", c.Key, c.Scanner, err)
		}
		return
	}
	if err := db.MarkDone(w.gdb, c.FileID, c.Scanner); err != nil {
		log.Printf("async: marking done %s/%s: %v", c.Key, c.Scanner, err)
	}
	log.Printf("async: %s/%s -> match=%v severity=%s (token %s)",
		c.Key, c.Scanner, f.Match, f.Severity, c.Token)
}

// ErrNoCollectors is returned when the worker would have nothing to do.
var ErrNoCollectors = errors.New("async: no collectors enabled")
