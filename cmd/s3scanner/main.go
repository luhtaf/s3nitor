package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luhtaf/s3nitor/internal/async"
	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/intel"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/pipeline"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/sandbox"
	"github.com/luhtaf/s3nitor/internal/scanner"
	"github.com/luhtaf/s3nitor/internal/source"
	"github.com/luhtaf/s3nitor/internal/source/decoder"
	"github.com/luhtaf/s3nitor/internal/source/transport"
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

	src, err := buildSource(cfg, fetcher)
	if err != nil {
		return err
	}
	defer src.Close()

	refs, err := src.Items(ctx)
	if err != nil {
		return err
	}

	// The threat-intel scanners are composed here rather than inside NewEngine:
	// they need the cache, and wiring them in the scanner package would create
	// an import cycle.
	scanners := scanner.NewEngine(cfg).Scanners()
	scanners = append(scanners, intel.NewOTX(cfg, gdb), intel.NewVirusTotal(cfg, gdb))

	// The sandbox is the one scanner that does not answer from the call that
	// starts it: it submits and hands back a token, and s3nitor-async collects
	// the verdict. Registering it here is what makes objects get submitted;
	// without the async worker running, they are submitted and never collected.
	scanners = append(scanners, sandbox.New(cfg))

	p := pipeline.New(cfg, fetcher, scanner.NewEngineWith(scanners...), rep, gdb, m, workDir)

	// Kafka only makes the handoff prompt. With no broker the ledger still
	// records every continuation and the worker's sweeper finds it, so lister
	// mode does not acquire a broker dependency by enabling a sandbox.
	if cfg.EventTransport == "kafka" && len(cfg.KafkaBrokers) > 0 {
		pub := async.NewKafkaPublisher(cfg.KafkaBrokers, cfg.AsyncTopic)
		defer pub.Close()
		p.SetAsyncPublisher(pub)
		log.Printf("handoff: kafka topic %q", cfg.AsyncTopic)
	}
	summary, err := p.Run(ctx, refs)
	if err != nil {
		return err
	}

	logSummary(summary)
	return nil
}

// buildSource picks where work comes from.
//
// One mode or the other, chosen by configuration rather than run together. A
// hybrid — events plus a periodic reconciling sweep — is the better answer for
// production, since event delivery does go missing when a broker is down or a
// notification rule is added after the bucket already had objects in it. It is
// deliberately not built yet: it needs a schedule and a way to tell a
// reconciling pass from a live one, and neither belongs in the first version.
func buildSource(cfg *config.Config, fetcher *s3fetcher.S3Fetcher) (source.Source, error) {
	switch cfg.SourceMode {
	case "", "lister":
		log.Println("source: lister")
		return source.NewLister(fetcher), nil

	case "event":
		dec, err := buildDecoder(cfg)
		if err != nil {
			return nil, err
		}
		switch cfg.EventTransport {
		case "redis":
			log.Printf("source: event, redis list %q on %s", cfg.RedisKey, cfg.RedisAddr)
			return source.NewEvent(
				transport.NewRedis(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisKey, cfg.RedisDB),
				dec), nil
		case "kafka":
			log.Printf("source: event, kafka topic %q group %q", cfg.KafkaTopic, cfg.KafkaGroupID)
			return source.NewEvent(
				transport.NewKafka(cfg.KafkaBrokers, cfg.KafkaTopic, cfg.KafkaGroupID),
				dec), nil
		default:
			return nil, fmt.Errorf("EVENT_TRANSPORT=%q is not supported; use redis or kafka", cfg.EventTransport)
		}

	default:
		return nil, fmt.Errorf("SOURCE_MODE=%q is not supported; use lister or event", cfg.SourceMode)
	}
}

// buildDecoder selects how payloads are read.
//
// Only MinIO is implemented, and it is selected explicitly rather than sniffed.
// Automatic detection is workable for the JSON formats, whose markers are
// distinctive, but not for SeaweedFS: protobuf is not self-describing, so random
// bytes frequently parse as a "valid" message with unknown fields. Guessing
// there produces silent misdecoding, which is worse than refusing.
func buildDecoder(cfg *config.Config) (source.Decoder, error) {
	switch cfg.EventFormat {
	case "", "minio":
		return decoder.MinIO{}, nil
	default:
		return nil, fmt.Errorf("EVENT_FORMAT=%q is not implemented yet; only minio is", cfg.EventFormat)
	}
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
		log.Printf("run summary: listed=%d scanned=%d skipped=%d failed=%d spilled=%d duration=%s rate=%.1f/s peak_rss=unavailable (%v)",
			s.Listed, s.Scanned, s.Skipped, s.Failed, s.Spilled, s.Duration.Round(time.Millisecond), rate, err)
		return
	}

	log.Printf("run summary: listed=%d scanned=%d skipped=%d failed=%d spilled=%d duration=%s rate=%.1f/s peak_rss=%d peak_rss_human=%s peak_rss_source=%s",
		s.Listed, s.Scanned, s.Skipped, s.Failed, s.Spilled,
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
