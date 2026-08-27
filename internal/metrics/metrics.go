// Package metrics exposes what the pipeline is doing, over a pull endpoint.
//
// This replaces internal/reporter/prometheus.go, which could not have worked:
// it built a metrics document and then discarded it, POSTing an empty body to
// /metrics. Prometheus scrapes; it does not accept pushes.
//
// Instrumentation lands with the pipeline rather than after it because the
// per-stage numbers are the only way to tell whether a limit is set correctly.
// Without them, sizing the deployment is guesswork from the outside.
package metrics

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// limiterStat is the slice of a limiter this package needs, declared here so
// metrics does not import pipeline and create a cycle.
type limiterStat interface {
	Name() string
	Limit() int64
	InFlight() int64
}

// Metrics holds the collectors and its own registry.
//
// A private registry rather than the default one: the default carries Go
// runtime and process collectors that would otherwise appear whether or not
// they were wanted, and a test that builds two Metrics would panic on
// duplicate registration.
type Metrics struct {
	reg *prometheus.Registry

	StageItems      *prometheus.CounterVec
	StageDuration   *prometheus.HistogramVec
	QueueDepth      *prometheus.GaugeVec
	Findings        *prometheus.CounterVec
	ObjectsSkipped  *prometheus.CounterVec
	PublishFlush    *prometheus.CounterVec
	PublishBatchLen *prometheus.HistogramVec
}

// New builds the collectors, including the Go runtime ones — heap size and
// goroutine count matter when the question is how much memory to request.
func New() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}

	m.StageItems = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "s3nitor_stage_items_total",
		Help: "Items leaving a stage, by outcome.",
	}, []string{"stage", "outcome"})

	m.StageDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "s3nitor_stage_duration_seconds",
		Help: "Time spent handling one item in a stage.",
		// Spans microseconds (an IOC map lookup) to minutes (a large transfer),
		// so the default buckets are far too narrow at both ends.
		Buckets: prometheus.ExponentialBuckets(0.001, 3, 12),
	}, []string{"stage"})

	m.QueueDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "s3nitor_queue_depth",
		Help: "Items waiting on a stage's input channel.",
	}, []string{"stage"})

	m.Findings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "s3nitor_findings_total",
		Help: "Scanner verdicts, by scanner and severity.",
	}, []string{"scanner", "severity"})

	m.ObjectsSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "s3nitor_objects_skipped_total",
		Help: "Objects not scanned, by reason.",
	}, []string{"reason"})

	m.PublishFlush = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "s3nitor_publish_flush_total",
		Help: "Batch flushes, by which trigger fired first.",
	}, []string{"trigger"})

	m.PublishBatchLen = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "s3nitor_publish_batch_size",
		Help:    "Documents per flush.",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	}, []string{"trigger"})

	m.reg.MustRegister(
		m.StageItems, m.StageDuration, m.QueueDepth,
		m.Findings, m.ObjectsSkipped, m.PublishFlush, m.PublishBatchLen,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// WatchLimiter publishes a limiter's bound and current occupancy.
//
// Registered as gauge functions rather than gauges a stage has to remember to
// update: the value is read at scrape time, so it cannot drift out of date and
// costs nothing when nobody is scraping.
func (m *Metrics) WatchLimiter(l limiterStat) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "s3nitor_limiter_limit",
		Help:        "Configured bound for a limiter, in its own units.",
		ConstLabels: prometheus.Labels{"limiter": l.Name()},
	}, func() float64 { return float64(l.Limit()) }))

	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "s3nitor_limiter_inflight",
		Help:        "Currently admitted work for a limiter, in its own units.",
		ConstLabels: prometheus.Labels{"limiter": l.Name()},
	}, func() float64 { return float64(l.InFlight()) }))
}

// ObserveStage records one item's passage through a stage.
func (m *Metrics) ObserveStage(stage string, started time.Time, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	m.StageItems.WithLabelValues(stage, outcome).Inc()
	m.StageDuration.WithLabelValues(stage).Observe(time.Since(started).Seconds())
}

// Handler serves the metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Serve runs the metrics endpoint until ctx is done. A blank addr disables it.
//
// Failing to bind is logged rather than fatal: losing observability should not
// stop a scan that would otherwise have completed.
func (m *Metrics) Serve(ctx context.Context, addr string) {
	if addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		log.Printf("metrics listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server stopped: %v", err)
		}
	}()
}
