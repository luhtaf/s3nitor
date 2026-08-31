// Package transport carries notification bytes from a broker.
package transport

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/luhtaf/s3nitor/internal/source"
)

// Redis consumes a list that MinIO pushes events onto.
//
// Note the durability this cannot offer: BRPOP removes the message as it reads
// it, so there is nothing to acknowledge. A consumer that dies after popping and
// before finishing has lost that event permanently — measured directly in phase
// 0, where the list went from three entries to two and the popped event was
// gone. Fine for development; use Kafka where a missed event means a missed
// detection.
type Redis struct {
	client *redis.Client
	key    string
}

func NewRedis(addr, password, key string, dbIndex int) *Redis {
	return &Redis{
		client: redis.NewClient(&redis.Options{
			Addr: addr, Password: password, DB: dbIndex,
		}),
		key: key,
	}
}

func (r *Redis) Consume(ctx context.Context) (<-chan source.Delivery, error) {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	out := make(chan source.Delivery)
	go func() {
		defer close(out)
		for {
			// A timeout rather than an indefinite block, so cancellation is
			// noticed promptly instead of after the next message arrives.
			res, err := r.client.BRPop(ctx, time.Second, r.key).Result()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue // timed out with an empty list
				}
				if ctx.Err() != nil {
					return
				}
				log.Printf("redis: %v", err)
				time.Sleep(time.Second)
				continue
			}
			// BRPop returns [key, value].
			if len(res) < 2 {
				continue
			}

			select {
			case out <- source.Delivery{
				Payload: []byte(res[1]),
				// Nothing to acknowledge: the pop already consumed it. Naming
				// that here rather than leaving a nil func keeps the gap
				// visible at the call site.
				Ack: func() error { return nil },
			}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (r *Redis) Close() error { return r.client.Close() }
