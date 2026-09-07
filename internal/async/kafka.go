package async

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
)

// KafkaPublisher writes continuations to the async topic.
//
// A separate topic from bucket notifications, not a separate broker. The two
// message kinds differ in lifetime rather than in origin: an event is consumed
// in milliseconds, while a continuation may be re-queued for hours as a sandbox
// works. Sharing one topic on one partition would put an analysis that polls for
// an hour in front of the next upload, because a Kafka partition is delivered in
// order — the slow message does not step aside.
type KafkaPublisher struct {
	w *kafka.Writer
}

func NewKafkaPublisher(brokers []string, topic string) *KafkaPublisher {
	return &KafkaPublisher{w: &kafka.Writer{
		Addr:  kafka.TCP(brokers...),
		Topic: topic,
		// Keyed by FileID+scanner so every continuation for one task lands on
		// the same partition and is therefore re-delivered in order. Without a
		// key, a re-queued poll could overtake the one before it, and the
		// verdict a later message carries could be published before an earlier
		// one marks the task done.
		Balancer:     &kafka.Hash{},
		BatchTimeout: 100 * time.Millisecond,
		// Wait for the broker to acknowledge. The ledger already holds the
		// token, so a lost write costs only promptness — but the whole reason
		// this publisher exists is promptness, and a silent drop would quietly
		// hand every continuation to the sweeper's slower path.
		RequiredAcks: kafka.RequireOne,
	}}
}

func (p *KafkaPublisher) Publish(ctx context.Context, c Continuation) error {
	body, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return p.w.WriteMessages(ctx, kafka.Message{
		Key:   []byte(c.FileID + "\x00" + c.Scanner),
		Value: body,
	})
}

func (p *KafkaPublisher) Close() error { return p.w.Close() }

// KafkaConsumer reads continuations back.
type KafkaConsumer struct {
	r *kafka.Reader
}

func NewKafkaConsumer(brokers []string, topic, groupID string) *KafkaConsumer {
	return &KafkaConsumer{r: kafka.NewReader(kafka.ReaderConfig{
		Brokers: brokers,
		Topic:   topic,
		GroupID: groupID,
		// Manual commits, as on the event topic: the offset moves when the work
		// is settled, not when the message is read.
		CommitInterval: 0,
	})}
}

// Delivery is one continuation and the means to acknowledge it.
type Delivery struct {
	Continuation Continuation
	Ack          func() error
}

// Consume yields continuations until the context ends.
//
// A message that cannot be decoded is acknowledged and dropped rather than
// retried: it will not decode on redelivery either, and leaving it uncommitted
// stalls the partition behind one bad message forever.
func (c *KafkaConsumer) Consume(ctx context.Context) (<-chan Delivery, error) {
	out := make(chan Delivery)
	go func() {
		defer close(out)
		for {
			msg, err := c.r.FetchMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("async: fetch: %v", err)
				continue
			}

			commit := func() error {
				return c.r.CommitMessages(context.WithoutCancel(ctx), msg)
			}

			var cont Continuation
			if err := json.Unmarshal(msg.Value, &cont); err != nil {
				log.Printf("async: undecodable continuation, skipping: %v", err)
				if e := commit(); e != nil {
					log.Printf("async: commit: %v", e)
				}
				continue
			}

			select {
			case out <- Delivery{Continuation: cont, Ack: commit}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (c *KafkaConsumer) Close() error { return c.r.Close() }
