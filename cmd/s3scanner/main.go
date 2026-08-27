package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/metrics"
	"github.com/luhtaf/s3nitor/internal/pipeline"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/scanner"
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
	if err := p.Run(ctx, objects); err != nil {
		return err
	}

	log.Println("done scanning S3 bucket")
	return nil
}
