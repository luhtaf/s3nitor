package source

import (
	"context"

	"github.com/luhtaf/s3nitor/internal/s3fetcher"
)

// Lister walks a bucket page by page.
//
// The right source for a backfill, an audit, or storage with no notification
// support. Wrong for steady state: detection latency is whatever the schedule
// is, and every run pages through the whole bucket to find the few objects that
// changed.
type Lister struct {
	fetcher *s3fetcher.S3Fetcher
}

func NewLister(f *s3fetcher.S3Fetcher) *Lister { return &Lister{fetcher: f} }

// Items streams the bucket rather than returning a slice.
//
// A channel because the previous design pulled every object's metadata into
// memory before a single worker started, so memory scaled with object count
// ahead of any work being done. Streaming also gives the two sources one shape,
// which matters because an event source never ends.
func (l *Lister) Items(ctx context.Context) (<-chan ObjectRef, error) {
	objects, err := l.fetcher.ListObjects(ctx)
	if err != nil {
		return nil, err
	}

	out := make(chan ObjectRef)
	go func() {
		defer close(out)
		for _, o := range objects {
			select {
			case out <- ObjectRef{
				Bucket:       o.Bucket,
				Key:          o.Key,
				Version:      o.ETag,
				Size:         o.Size,
				LastModified: o.LastModified,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (l *Lister) Close() error { return nil }
