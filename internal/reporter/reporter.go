package reporter

import (
	"context"
)

type Reporter interface {
	Report(ctx context.Context, result map[string]interface{}) error
}
