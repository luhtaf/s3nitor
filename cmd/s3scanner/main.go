package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/pipeline"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/scanner"
	"github.com/luhtaf/s3nitor/internal/sysinfo"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run holds the body so deferred cleanup actually executes: log.Fatal calls
// os.Exit, which skips defers, so the work directory would otherwise be left
// behind on any fatal path.
func run() error {
	log.Printf("s3nitor %s starting", Version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("signal received, draining")
		cancel()
	}()

	cfg := config.Load()

	m := metrics.New()
	m.Serve(ctx, cfg.MetricsAddr)

	gdb, err := db.NewDB(cfg)
	if err != nil {
		return err
	}
	if err := db.Migrate(gdb); err != nil {
		return err
	}

	rep, err := reporter.Build(cfg)
	if err != nil {
		return err
	}

	fetcher, err := s3fetcher.NewS3Fetcher(cfg)
	if err != nil {
		return err
	}

	// One work directory per run, removed on the way out. Named so that a
	// process killed mid-scan leaves an identifiable directory rather than
	// scattering orphans through the system temp dir.
	workDir, err := os.MkdirTemp("", "s3nitor-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	objects, err := fetcher.ListObjects(ctx)
	if err != nil {
		return err
	}
	log.Printf("listed %d objects", len(objects))

	p := pipeline.New(cfg, fetcher, scanner.NewEngine(cfg), rep, gdb, m, workDir)
	summary, err := p.Run(ctx, objects)
	if err != nil {
		return err
	}

	logSummary(summary)
	return nil
}

// logSummary prints one machine-readable line describing the run.
//
// Emitted to the log rather than left to the metrics endpoint because a
// single-shot job's endpoint dies with the process: by the time anything
// scrapes it, the run is over. A benchmark harness reads this line instead.
//
// Peak memory comes from the cgroup or VmHWM, not runtime.MemStats. MemStats
// covers the Go heap, while the SQLite driver is cgo and allocates outside it —
// so a run can look comfortable there and still be OOM-killed. The source is
// printed alongside the figure, since a cgroup reading and a getrusage one are
// not comparable.
func logSummary(s pipeline.Summary) {
	rate := 0.0
	if secs := s.Duration.Seconds(); secs > 0 {
		rate = float64(s.Scanned) / secs
	}

	peak, source, err := sysinfo.PeakRSS()
	if err != nil {
		log.Printf("run summary: listed=%d scanned=%d skipped=%d failed=%d duration=%s rate=%.1f/s peak_rss=unavailable (%v)",
			s.Listed, s.Scanned, s.Skipped, s.Failed, s.Duration.Round(time.Millisecond), rate, err)
		return
	}

	log.Printf("run summary: listed=%d scanned=%d skipped=%d failed=%d duration=%s rate=%.1f/s peak_rss=%d peak_rss_human=%s peak_rss_source=%s",
		s.Listed, s.Scanned, s.Skipped, s.Failed,
		s.Duration.Round(time.Millisecond), rate,
		peak, humanBytes(peak), source)
}

// humanBytes renders a byte count for the log line; the raw figure is printed
// beside it so a harness never has to parse this.
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
