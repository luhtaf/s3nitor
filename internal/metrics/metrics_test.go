package metrics

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeLimiter stands in for a pipeline limiter.
type fakeLimiter struct {
	name     string
	limit    int64
	inFlight int64
}

func (f fakeLimiter) Name() string    { return f.name }
func (f fakeLimiter) Limit() int64    { return f.limit }
func (f fakeLimiter) InFlight() int64 { return f.inFlight }

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("scrape returned %d", rec.Code)
	}
	return rec.Body.String()
}

func TestScrapeExposesStageAndLimiterSeries(t *testing.T) {
	m := New()
	m.WatchLimiter(fakeLimiter{name: "fetch", limit: 536870912, inFlight: 1024})

	m.ObserveStage("fetch", time.Now().Add(-50*time.Millisecond), nil)
	m.ObserveStage("analyze", time.Now(), errors.New("boom"))
	m.Findings.WithLabelValues("yara", "medium").Inc()
	m.ObjectsSkipped.WithLabelValues("too_large").Inc()
	m.PublishFlush.WithLabelValues("interval").Inc()

	body := scrape(t, m)

	for _, want := range []string{
		`s3nitor_stage_items_total{outcome="ok",stage="fetch"} 1`,
		`s3nitor_stage_items_total{outcome="error",stage="analyze"} 1`,
		`s3nitor_findings_total{scanner="yara",severity="medium"} 1`,
		`s3nitor_objects_skipped_total{reason="too_large"} 1`,
		`s3nitor_publish_flush_total{trigger="interval"} 1`,
		`s3nitor_limiter_limit{limiter="fetch"} 5.36870912e+08`,
		`s3nitor_limiter_inflight{limiter="fetch"} 1024`,
		"s3nitor_stage_duration_seconds_bucket",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing %q", want)
		}
	}

	// Sizing the deployment needs the runtime's own numbers, not just ours.
	for _, want := range []string{"go_goroutines", "go_memstats_heap_inuse_bytes"} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape is missing the runtime series %q", want)
		}
	}
}

// A private registry means two instances can coexist; on the default registry
// the second would panic on duplicate registration, which would make any test
// that builds a pipeline unrunnable alongside another.
func TestTwoInstancesDoNotCollide(t *testing.T) {
	a, b := New(), New()
	a.WatchLimiter(fakeLimiter{name: "fetch", limit: 1})
	b.WatchLimiter(fakeLimiter{name: "fetch", limit: 2})

	if !strings.Contains(scrape(t, b), `s3nitor_limiter_limit{limiter="fetch"} 2`) {
		t.Error("the second registry does not hold its own value")
	}
}
