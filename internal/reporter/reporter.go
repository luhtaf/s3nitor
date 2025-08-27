package reporter

import (
	"context"

	"github.com/luhtaf/s3nitor/internal/scanner"
)

type Reporter interface {
	Report(ctx context.Context, sc *scanner.ScanContext) error
}
