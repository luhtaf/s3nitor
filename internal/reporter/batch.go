package reporter

import (
	"context"

	"github.com/luhtaf/s3nitor/internal/scanner"
)

// BatchReporter is an optional upgrade for reporters whose sink accepts many
// documents in one request.
//
// Declared separately rather than added to Reporter so that a sink with no
// batch API — a file, a log line — does not have to pretend to have one. The
// publish stage type-asserts for it and falls back to Report per document.
type BatchReporter interface {
	ReportBatch(ctx context.Context, batch []*scanner.Finding) error
}
