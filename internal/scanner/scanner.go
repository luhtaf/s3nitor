package scanner

import (
	"context"
	"errors"
	"log"

	"github.com/luhtaf/s3nitor/internal/config"
)

// NewEngine registers the scanners that need nothing beyond config.
//
// The threat-intel scanners are not built here: they need the cache, which lives
// in db, and putting them under this package would force scanner to import intel
// while intel imports scanner for this interface. The caller composes the full
// set with NewEngineWith.
//
// Registration order no longer matters. It used to: HashScanner had to come
// first because IOC and OTX read the hashes it left in the shared context.
// Hashing now happens during the fetch and arrives as ScanInput.Hashes, so the
// scanners have no dependency on one another and may run in any order — or at
// the same time.
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{}
	if cfg.EnableIOC {
		e.scanners = append(e.scanners, NewIOCScanner(cfg))
	}
	if cfg.EnableYara {
		e.scanners = append(e.scanners, NewYaraScanner(cfg))
	}
	return e
}

// ScanOne runs a single scanner and returns its published verdict.
//
// A scanner failure becomes a Finding carrying the error rather than a dropped
// result. The old ProcessFile logged the error and moved on, which left no trace
// once the pod was gone — and for a security scanner, "this check did not run"
// has to be as visible as "this check found nothing".
func ScanOne(ctx context.Context, s Scanner, in *ScanInput) *Finding {
	res, err := RunScan(ctx, s, in)
	if err != nil {
		log.Printf("[%s] %s: %v", s.Name(), in.Key, err)
	}
	return NewFinding(in, s, res, err)
}

// RunScan calls a scanner under its own deadline.
//
// The deadline is derived from the caller's context rather than replacing it,
// so cancelling the run still cancels the scan; the timeout only ever makes the
// bound tighter.
//
// A *PendingError comes back unwrapped on purpose. Wrapping it in "deadline
// exceeded" would be accurate and useless: the caller has to tell "this failed"
// from "this is still running elsewhere, here is how to find it", and only the
// second one carries a token worth keeping.
func RunScan(ctx context.Context, s Scanner, in *ScanInput) (Result, error) {
	if d := s.Timeout(); d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	return s.Scan(ctx, in)
}

// AsPending reports whether an error is a handoff rather than a failure.
func AsPending(err error) (*PendingError, bool) {
	var pe *PendingError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// NewEngineWith builds an engine from an explicit scanner set.
//
// For tests and for callers that assemble the set themselves; NewEngine reads
// the config, which is the wrong seam when the point is to control exactly which
// scanners run.
func NewEngineWith(scanners ...Scanner) *Engine {
	return &Engine{scanners: scanners}
}
