package transport

import (
	"context"
	"log"

	"github.com/segmentio/kafka-go"

	"github.com/luhtaf/s3nitor/internal/source"
)

// Kafka consumes a topic as part of a consumer group.
//
// segmentio/kafka-go rather than confluent-kafka-go: it is pure Go, and this
// project is already constrained by one cgo dependency (the SQLite driver). A
// second would make building for anything but the host platform harder still.
//
// Unlike a Redis list, this can acknowledge. Offsets are committed only after a
// message has been fully handled, so a consumer that dies mid-scan sees the same
// message again rather than losing it — verified in phase 0 by killing a
// consumer before it committed.
type Kafka struct {
	reader *kafka.Reader
}

func NewKafka(brokers []string, topic, groupID string) *Kafka {
	return &Kafka{reader: kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		Topic:   topic,
		GroupID: groupID,
		// Manual commits: the whole point is that the offset moves after the
		// work is done, not when the message is read.
		CommitInterval: 0,
	})}
}

func (k *Kafka) Consume(ctx context.Context) (<-chan source.Delivery, error) {
	out := make(chan source.Delivery)
	go func() {
		defer close(out)
		for {
			msg, err := k.reader.FetchMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("kafka: %v", err)
				continue
			}

			select {
			case out <- source.Delivery{
				Payload: msg.Value,
				Ack: func() error {
					// Committing here, after the caller says it is done, is what
					// makes redelivery-on-crash work.
					return k.reader.CommitMessages(context.WithoutCancel(ctx), msg)
				},
			}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (k *Kafka) Close() error { return k.reader.Close() }
