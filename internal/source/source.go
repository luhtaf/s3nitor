// Package source decides where work comes from.
//
// Two modes, chosen by configuration. The lister paginates a bucket, which is
// right for backfills, audits, and storage with no notification support. The
// event source consumes bucket notifications, which is right for steady state:
// detection latency stops being the cron interval, and a run stops paging
// through ten million objects to find the four that changed.
package source

import (
	"context"
	"time"
)

// ObjectRef is one object to consider scanning.
//
// Version rather than ETag: SeaweedFS has no S3-style ETag, and what dedup
// actually needs is any token that changes when the content does. Which field
// supplies it is the decoder's problem, not the pipeline's.
type ObjectRef struct {
	Bucket       string
	Key          string
	Version      string
	Size         int64
	LastModified time.Time
}

// Source produces objects until it is exhausted or the context ends.
type Source interface {
	Items(ctx context.Context) (<-chan ObjectRef, error)
	Close() error
}

// Delivery is one message from a transport, with the acknowledgement that
// belongs to it.
type Delivery struct {
	Payload []byte
	// Ack is called once the message has been fully handled. For Kafka this
	// commits the offset; for a Redis list it does nothing, because the pop
	// already removed the message — which is precisely the durability gap
	// between the two.
	Ack func() error
}

// Transport is where bytes arrive from.
type Transport interface {
	Consume(ctx context.Context) (<-chan Delivery, error)
	Close() error
}

// Decoder turns a transport payload into object references.
//
// Separate from Transport because the two vary independently — but not as
// independently as first assumed. Measurement showed the same MinIO instance
// wraps the identical event differently depending on where it is delivered:
// {"Records":[…]} to Kafka, [{"Event":[…]}] to Redis. So a decoder has to
// recognise the envelope, not just the vendor.
//
// One message can carry several records, hence the slice.
type Decoder interface {
	Decode(payload []byte) ([]ObjectRef, error)
}
