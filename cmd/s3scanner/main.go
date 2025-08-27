package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Trap signal untuk graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Load config
	cfg := config.Load()

	// Init DB
	gdb, err := db.NewDB(cfg)
	if err != nil {
		log.Fatalf("failed init DB: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		log.Fatalf("failed migrate DB: %v", err)
	}

	// Worker count
	workerCount := cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	// Init scanner engine
	engine := scanner.NewEngine(cfg)

	// Init reporter
	rep, err := reporter.Build(cfg)
	if err != nil {
		log.Fatalf("failed init reporter: %v", err)
	}

	// Init S3 fetcher
	fetcher, err := s3fetcher.NewS3Fetcher(cfg)
	if err != nil {
		log.Fatalf("failed init s3 fetcher: %v", err)
	}

	// List metadata S3 objects
	objects, err := fetcher.ListObjects(ctx)
	if err != nil {
		log.Fatalf("failed list s3 objects: %v", err)
	}

	jobs := make(chan s3fetcher.S3Object, len(objects))
	wg := &sync.WaitGroup{}

	// Worker pool
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Cek DB sebelum download
				record := &db.FileRecord{}
				tx := gdb.Where("bucket=? AND object_key=?", cfg.S3Bucket, j.Key).First(&record)
				if tx.Error == nil {
					if record.ETag == j.ETag && !record.UpdatedAt.Before(j.LastModified) {
						log.Printf("[worker %d] skip %s, already scanned", id, j.Key)
						continue
					}
				}

				// Download file S3
				localPath, err := fetcher.Download(ctx, j.Key)
				if err != nil {
					log.Printf("[worker %d] download error: %v", id, err)
					continue
				}

				// Scan file → hasilnya dikirim ke reporter
				results, err := engine.ProcessFile(ctx, j, localPath)
				if err != nil {
					log.Printf("[worker %d] scan error: %v", id, err)
				} else {
					if err := rep.Report(ctx, results); err != nil {
						log.Printf("[worker %d] reporter error: %v", id, err)
					}
				}

				// Update DB
				record.Bucket = cfg.S3Bucket
				record.ObjectKey = j.Key
				record.ETag = j.ETag
				record.ScanTime = time.Now()
				if err := db.UpsertFileRecord(gdb, record); err != nil {
					log.Printf("[worker %d] db update error: %v", id, err)
				}

				// Cleanup
				os.Remove(localPath)
			}
		}(i)
	}

	// Feed jobs
	for _, obj := range objects {
		jobs <- obj
	}
	close(jobs)

	wg.Wait()
	log.Println("done scanning S3 bucket")
}
