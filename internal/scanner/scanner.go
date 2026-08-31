package scanner

import (
	"context"
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
	res, err := s.Scan(ctx, in)
	if err != nil {
		log.Printf("[%s] %s: %v", s.Name(), in.Key, err)
	}
	return NewFinding(in, s, res, err)
}

// NewEngineWith builds an engine from an explicit scanner set.
//
// For tests and for callers that assemble the set themselves; NewEngine reads
// the config, which is the wrong seam when the point is to control exactly which
// scanners run.
func NewEngineWith(scanners ...Scanner) *Engine {
	return &Engine{scanners: scanners}
}
