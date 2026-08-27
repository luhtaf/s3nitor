package pipeline

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestFixedLimiterBoundsConcurrency(t *testing.T) {
	const limit = 3
	l := NewFixedLimiter("test", limit)

	var mu sync.Mutex
	var current, peak int

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire(context.Background(), 999)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			defer release(Outcome{})

			mu.Lock()
			current++
			if current > peak {
				peak = current
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if peak > limit {
		t.Errorf("peak concurrency = %d, limit = %d", peak, limit)
	}
	if l.InFlight() != 0 {
		t.Errorf("InFlight() = %d after everything released, want 0", l.InFlight())
	}
}

// The claim the byte budget exists to make: what is bounded is total bytes, not
// item count, so the number of items admitted depends on how large they are.
func TestByteLimiterBoundsBytesNotCount(t *testing.T) {
	const budget = 1000
	l := NewByteLimiter("fetch", budget)
	ctx := context.Background()

	// Ten small items fit inside the same budget as one large item.
	var releases []func(Outcome)
	for i := 0; i < 10; i++ {
		release, err := l.Acquire(ctx, 100)
		if err != nil {
			t.Fatalf("small item %d: %v", i, err)
		}
		releases = append(releases, release)
	}
	if got := l.InFlight(); got != budget {
		t.Errorf("InFlight() = %d, want %d", got, budget)
	}

	// The budget is now exhausted: one more byte must not be admitted.
	tight, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(tight, 1); err == nil {
		t.Error("acquired past the byte budget")
	}

	for _, release := range releases {
		release(Outcome{})
	}
	if l.InFlight() != 0 {
		t.Errorf("InFlight() = %d after release, want 0", l.InFlight())
	}
}

// An object larger than the whole budget must still make progress. Passing it
// straight to semaphore.Weighted would block until the context died.
func TestByteLimiterClampsOversizedItems(t *testing.T) {
	l := NewByteLimiter("fetch", 1000)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		release, err := l.Acquire(ctx, 999_999_999)
		if err != nil {
			t.Errorf("oversized acquire failed instead of clamping: %v", err)
			return
		}
		release(Outcome{})
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("an oversized item deadlocked the limiter")
	}
}

func TestLimitersRespectContextCancellation(t *testing.T) {
	for _, l := range []Limiter{
		NewFixedLimiter("cpu", 1),
		NewByteLimiter("fetch", 10),
	} {
		t.Run(l.Name(), func(t *testing.T) {
			hold, err := l.Acquire(context.Background(), 10)
			if err != nil {
				t.Fatalf("first acquire: %v", err)
			}
			defer hold(Outcome{})

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := l.Acquire(ctx, 10); err == nil {
				t.Error("acquired with a cancelled context")
			}
		})
	}
}

// Release is called from deferred paths that can run more than once during
// shutdown; double-releasing must not corrupt the accounting.
func TestReleaseIsIdempotent(t *testing.T) {
	l := NewByteLimiter("fetch", 100)
	release, err := l.Acquire(context.Background(), 50)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release(Outcome{})
	release(Outcome{})

	if l.InFlight() != 0 {
		t.Errorf("InFlight() = %d after a double release, want 0", l.InFlight())
	}
	if _, err := l.Acquire(context.Background(), 100); err != nil {
		t.Errorf("budget was corrupted by the double release: %v", err)
	}
}
