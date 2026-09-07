// Command s3nitor-async collects verdicts for scans that were handed off.
//
// A separate binary and a separate runtime from the scanner, because the two
// have nothing in common at runtime. The scanner is bounded by bytes in flight
// and CPU; this waits on somebody else's analysis and uses almost nothing. Run
// together, the scanner's memory limit would have to cover both, and a restart
// of one would interrupt the other.
//
// Note what it does not need: S3 credentials, a work directory, a byte budget.
// The object went to the sandbox when it was submitted, so collecting a verdict
// is a poll by token — never a download.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/luhtaf/s3nitor/internal/async"
	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/sandbox"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	log.Printf("s3nitor-async %s starting", Version)

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
	if c, ok := rep.(interface{ Close() error }); ok {
		defer c.Close()
	}

	// Only enabled collectors are registered. A continuation naming a scanner
	// nothing here can read is failed with a document rather than retried
	// forever — see Worker.handle.
	var collectors []async.Collector
	if sb := sandbox.New(cfg); sb.Enabled() {
		log.Printf("collector: %s at %s", sb.Name(), cfg.SandboxURL)
		collectors = append(collectors, sb)
	}
	if len(collectors) == 0 {
		// Refused rather than run idle. A worker with nothing to collect looks
		// healthy while every handed-off scan silently accumulates unread — the
		// exact failure this project keeps producing.
		return async.ErrNoCollectors
	}

	var consumer *async.KafkaConsumer
	if cfg.SourceMode == "event" && cfg.EventTransport == "kafka" {
		log.Printf("async: kafka topic %q group %q", cfg.AsyncTopic, cfg.AsyncGroupID)
		consumer = async.NewKafkaConsumer(cfg.KafkaBrokers, cfg.AsyncTopic, cfg.AsyncGroupID)
		defer consumer.Close()
	} else {
		// Without a broker the sweeper alone carries the work: slower to notice
		// a finished analysis, but nothing is lost, because the ledger — not the
		// topic — is what records the handoff.
		log.Println("async: no broker configured, sweeping the ledger only")
	}

	host, _ := os.Hostname()
	w := async.NewWorker(gdb, rep, consumer, collectors, async.WorkerOptions{
		Instance:     host,
		PollInterval: cfg.AsyncPollInterval,
		SweepEvery:   cfg.AsyncSweepInterval,
		MaxAge:       cfg.AsyncMaxAge,
	})

	log.Printf("async: poll every %s, sweep every %s, abandon after %s",
		cfg.AsyncPollInterval, cfg.AsyncSweepInterval, cfg.AsyncMaxAge)

	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	log.Println("async: stopped")
	return nil
}
