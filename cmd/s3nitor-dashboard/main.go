// Command s3nitor-dashboard serves a read-only view of the scanner's findings.
//
// A separate binary from the scanner on purpose. It has a different lifecycle —
// the scanner is a one-shot job, this runs continuously — a different failure
// mode, and a much wider audience. Keeping them apart means the thing more
// people can reach is the one that cannot write anything.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/dashboard"
	"github.com/luhtaf/s3nitor/internal/db"
)

var Version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	log.Printf("s3nitor-dashboard %s starting", Version)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := config.Load()
	if cfg.ESUrl == "" || cfg.ESIndex == "" {
		return errors.New("ES_URL and ES_INDEX are required: the dashboard reads findings from Elasticsearch")
	}

	es := dashboard.NewES(cfg.ESUrl, cfg.ESIndex, cfg.ESUsername, cfg.ESPassword, cfg.ESAPIKey)

	// The scanner's ledger is optional. It answers "what has not been done yet",
	// which Elasticsearch cannot — findings only exist for work that finished —
	// but the dashboard is useful without it, so a missing or unreachable
	// database degrades that one panel instead of refusing to start.
	var gdb *gorm.DB
	if cfg.DBDSN != "" && cfg.DBDriver != "" {
		var err error
		if gdb, err = db.NewDB(cfg); err != nil {
			log.Printf("queue panel disabled, cannot open the ledger: %v", err)
			gdb = nil
		} else {
			log.Printf("queue panel enabled via %s", cfg.DBDriver)
		}
	} else {
		log.Println("queue panel disabled: no DB_DRIVER/DB_DSN configured")
	}

	addr := os.Getenv("DASHBOARD_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           dashboard.NewServer(es, gdb).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Println("shutting down")
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("dashboard on %s, reading index %q from %s", addr, cfg.ESIndex, cfg.ESUrl)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
