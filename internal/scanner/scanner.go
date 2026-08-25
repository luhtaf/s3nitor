package scanner

import (
	"context"
	"log"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
)

// NewEngine registers the scanners enabled by config.
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
	if cfg.EnableOTX {
		e.scanners = append(e.scanners, NewOTXScanner(cfg))
	}
	if cfg.EnableYara {
		e.scanners = append(e.scanners, NewYaraScanner(cfg))
	}
	return e
}

// ProcessFile runs every enabled scanner over one object and collects the
// verdicts.
//
// Collecting here is a temporary arrangement. The staged pipeline publishes each
// scanner's result independently, at which point this function disappears along
// with FileResult.
//
// The outer envelope the reporters emit is unchanged, but the contents of
// "results" are not: each scanner used to invent its own keys ("ioc_match",
// "yara_match", "otx_match") inside an untyped map, so no consumer could ask
// "did anything match?" without knowing every scanner by name. Every entry is
// now the same {match, severity, detail} shape. Scanner names lost their
// "_scanner" suffix to match. Anything parsing the old output needs updating.
//
// A failing scanner is logged and skipped rather than aborting the others: one
// unreachable API should not cost you the YARA verdict.
func (e *Engine) ProcessFile(ctx context.Context, in *ScanInput) *FileResult {
	out := &FileResult{
		FileID:   in.FileID,
		Bucket:   in.Bucket,
		Key:      in.Key,
		Version:  in.Version,
		Size:     in.Size,
		Hashes:   in.Hashes,
		Results:  make(map[string]Result, len(e.scanners)),
		ScanTime: time.Now().UTC(),
	}

	for _, s := range e.scanners {
		if !s.Enabled() {
			continue
		}
		res, err := s.Scan(ctx, in)
		if err != nil {
			log.Printf("[%s] error: %v", s.Name(), err)
			continue
		}
		out.Results[s.Name()] = res
	}
	return out
}
