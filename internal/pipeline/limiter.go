// Package pipeline runs the scan as stages, each bounded by the resource it
// actually contends for.
//
// The previous design used one worker pool and one WORKER_COUNT for five kinds
// of work — a database query, a network transfer, CPU-bound scanning, a
// third-party API call, and a write to the sink. A single number cannot be
// right for all of them, so it ends up chosen for the worst case and slow
// everywhere else.
package pipeline

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

// Outcome reports how admitted work went.
//
// Static limiters ignore it. It exists so the adaptive limiter can arrive later
// without changing any call site: growing or shrinking a limit needs to be
// driven by downstream distress — rising latency, 429s, timeouts — and not by
// queue depth, which only says demand exceeds throughput and never says whether
// more concurrency would help.
type Outcome struct {
	Err     error
	Latency time.Duration
}

// Limiter admits work up to some bound.
//
// Acquire blocks until the work fits or ctx is done. The returned release must
// be called exactly once, whatever the result.
type Limiter interface {
	Name() string
	Acquire(ctx context.Context, weight int64) (release func(Outcome), err error)
	Limit() int64
	InFlight() int64
}

// FixedLimiter admits a fixed number of concurrent items and ignores weight.
//
// The right shape for CPU-bound work: the bound is core count, and every unit
// of work occupies one core regardless of how large its input is.
type FixedLimiter struct {
	name     string
	slots    chan struct{}
	limit    int64
	inFlight atomic.Int64
}

// NewFixedLimiter returns a limiter admitting at most n items at once.
func NewFixedLimiter(name string, n int) *FixedLimiter {
	if n < 1 {
		n = 1
	}
	return &FixedLimiter{
		name:  name,
		slots: make(chan struct{}, n),
		limit: int64(n),
	}
}

func (l *FixedLimiter) Name() string    { return l.name }
func (l *FixedLimiter) Limit() int64    { return l.limit }
func (l *FixedLimiter) InFlight() int64 { return l.inFlight.Load() }

func (l *FixedLimiter) Acquire(ctx context.Context, _ int64) (func(Outcome), error) {
	select {
	case l.slots <- struct{}{}:
		l.inFlight.Add(1)
		var once atomic.Bool
		return func(Outcome) {
			if once.CompareAndSwap(false, true) {
				l.inFlight.Add(-1)
				<-l.slots
			}
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ByteLimiter admits work against a budget measured in bytes, with a separate
// ceiling on how many items may be in flight at once.
//
// This is the whole point of the refactor. Bounding the fetch stage by file
// count means picking a number that is safe for the largest object you might
// ever meet, which makes it far too small for the ordinary case. Bounding by
// bytes admits fifty thousand 10 KB objects or one 512 MB object against the
// same budget, and both are correct.
type ByteLimiter struct {
	name     string
	bytes    *semaphore.Weighted
	conns    chan struct{}
	budget   int64
	inFlight atomic.Int64
}

// NewByteLimiter returns a limiter over budget bytes and maxConns transfers.
func NewByteLimiter(name string, budget int64, maxConns int) *ByteLimiter {
	if budget < 1 {
		budget = 1
	}
	if maxConns < 1 {
		maxConns = 1
	}
	return &ByteLimiter{
		name:   name,
		bytes:  semaphore.NewWeighted(budget),
		conns:  make(chan struct{}, maxConns),
		budget: budget,
	}
}

func (l *ByteLimiter) Name() string    { return l.name }
func (l *ByteLimiter) Limit() int64    { return l.budget }
func (l *ByteLimiter) InFlight() int64 { return l.inFlight.Load() }

// Acquire reserves weight bytes and one transfer slot.
//
// A weight larger than the entire budget is clamped rather than rejected.
// semaphore.Weighted blocks forever on an unsatisfiable request, so an object
// bigger than the budget would otherwise hang the stage until the context was
// cancelled. Clamping lets that object through on its own, which still bounds
// memory — one oversized object at a time — without silently dropping data.
// Skipping such objects entirely is what MAX_OBJECT_SIZE is for, and that
// decision belongs to the caller.
func (l *ByteLimiter) Acquire(ctx context.Context, weight int64) (func(Outcome), error) {
	if weight < 0 {
		return nil, fmt.Errorf("%s: negative weight %d", l.name, weight)
	}
	if weight < 1 {
		weight = 1 // an empty object still occupies a transfer slot
	}
	if weight > l.budget {
		weight = l.budget
	}

	select {
	case l.conns <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if err := l.bytes.Acquire(ctx, weight); err != nil {
		<-l.conns
		return nil, err
	}

	l.inFlight.Add(weight)
	var once atomic.Bool
	return func(Outcome) {
		if once.CompareAndSwap(false, true) {
			l.inFlight.Add(-weight)
			l.bytes.Release(weight)
			<-l.conns
		}
	}, nil
}
