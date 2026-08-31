package reporter

import (
	"context"

	"github.com/luhtaf/s3nitor/internal/scanner"
)

// Reporter publishes one finding.
//
// One finding rather than one file: scanners finish at very different times, so
// there is no moment at which "the result for this object" exists as a whole.
type Reporter interface {
	Report(ctx context.Context, f *scanner.Finding) error
}
