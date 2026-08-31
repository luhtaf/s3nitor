package source

import (
	"context"
	"log"
)

// Event turns broker messages into object references.
//
// Transport and Decoder are separate because they vary independently — MinIO can
// publish to Redis or Kafka, and Kafka can carry MinIO or Ceph events. Only
// partly independently, though: the same MinIO instance uses a different
// envelope per transport, so the decoder recognises envelopes rather than
// vendors.
type Event struct {
	transport Transport
	decoder   Decoder
}

func NewEvent(t Transport, d Decoder) *Event {
	return &Event{transport: t, decoder: d}
}

func (e *Event) Items(ctx context.Context) (<-chan ObjectRef, error) {
	deliveries, err := e.transport.Consume(ctx)
	if err != nil {
		return nil, err
	}

	out := make(chan ObjectRef)
	go func() {
		defer close(out)
		for d := range deliveries {
			refs, err := e.decoder.Decode(d.Payload)
			if err != nil {
				// Acknowledge anyway. A payload this consumer cannot parse will
				// not parse on redelivery either, so leaving it uncommitted
				// would stall the partition behind one bad message forever.
				log.Printf("event: undecodable payload, skipping: %v", err)
				if ackErr := d.Ack(); ackErr != nil {
					log.Printf("event: ack: %v", ackErr)
				}
				continue
			}

			for _, ref := range refs {
				select {
				case out <- ref:
				case <-ctx.Done():
					return
				}
			}

			// Acknowledged once the references are handed on.
			//
			// Note what this does and does not promise: the objects are queued,
			// not scanned. Delaying the commit until every scanner finished
			// would hold the partition for as long as the slowest quota-bound
			// lookup, which can be hours. Durability past this point is the scan
			// ledger's job, not the broker's.
			if err := d.Ack(); err != nil {
				log.Printf("event: ack: %v", err)
			}
		}
	}()
	return out, nil
}

func (e *Event) Close() error { return e.transport.Close() }
