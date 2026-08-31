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
	"golang.org/x/time/rate"
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

// ByteLimiter admits work against a budget measured in bytes.
//
// This is the whole point of the refactor. Bounding a stage by item count means
// picking a number safe for the largest object you might ever meet, which makes
// it far too small for the ordinary case. Bounding by bytes admits fifty
// thousand 10 KB objects or one 512 MB object against the same budget, and both
// are correct.
//
// It counts bytes only. Concurrency is a separate concern with a separate
// limiter, because the two are held for different spans: a connection is done
// once the transfer is, while the bytes stay resident on disk until the scanners
// have finished with them.
type ByteLimiter struct {
	name     string
	bytes    *semaphore.Weighted
	budget   int64
	inFlight atomic.Int64
}

// NewByteLimiter returns a limiter over budget bytes.
func NewByteLimiter(name string, budget int64) *ByteLimiter {
	if budget < 1 {
		budget = 1
	}
	return &ByteLimiter{
		name:   name,
		bytes:  semaphore.NewWeighted(budget),
		budget: budget,
	}
}

func (l *ByteLimiter) Name() string    { return l.name }
func (l *ByteLimiter) Limit() int64    { return l.budget }
func (l *ByteLimiter) InFlight() int64 { return l.inFlight.Load() }

// Acquire reserves weight bytes.
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
		weight = 1 // an empty object still occupies the pipeline
	}
	if weight > l.budget {
		weight = l.budget
	}

	if err := l.bytes.Acquire(ctx, weight); err != nil {
		return nil, err
	}

	l.inFlight.Add(weight)
	var once atomic.Bool
	return func(Outcome) {
		if once.CompareAndSwap(false, true) {
			l.inFlight.Add(-weight)
			l.bytes.Release(weight)
		}
	}, nil
}

// RateLimiter admits work at a fixed rate rather than a fixed concurrency.
//
// The right shape for a third-party API, where the constraint is requests per
// unit of time and not how many are in flight. A VirusTotal free-tier key allows
// four lookups per minute; expressing that as a concurrency limit would be
// meaningless, since one request at a time is still far too many if they come
// back quickly.
type RateLimiter struct {
	name     string
	lim      *rate.Limiter
	inFlight atomic.Int64
	perSec   float64
}

// NewRateLimiter admits perSec requests per second, allowing a burst of one.
//
// A burst of one on purpose: a larger burst spends the quota immediately and
// then stalls, which for a daily-capped API means running out early in the day
// rather than pacing across it.
func NewRateLimiter(name string, perSec float64) *RateLimiter {
	if perSec <= 0 {
		perSec = 1
	}
	return &RateLimiter{
		name:   name,
		lim:    rate.NewLimiter(rate.Limit(perSec), 1),
		perSec: perSec,
	}
}

func (l *RateLimiter) Name() string { return l.name }

// Limit reports requests per minute, since that is the unit these quotas are
// published in and a fractional per-second figure reads as noise.
func (l *RateLimiter) Limit() int64    { return int64(l.perSec * 60) }
func (l *RateLimiter) InFlight() int64 { return l.inFlight.Load() }

func (l *RateLimiter) Acquire(ctx context.Context, _ int64) (func(Outcome), error) {
	if err := l.lim.Wait(ctx); err != nil {
		return nil, err
	}
	l.inFlight.Add(1)
	var once atomic.Bool
	return func(Outcome) {
		if once.CompareAndSwap(false, true) {
			l.inFlight.Add(-1)
		}
	}, nil
}
