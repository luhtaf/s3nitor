package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/hashing"
	"github.com/luhtaf/s3nitor/internal/reporter"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
	"github.com/luhtaf/s3nitor/internal/scanner"

	"gorm.io/gorm"
)

// Version is set at build time via -ldflags "-X main.Version=..."
var Version = "dev"

func main() {
	log.Printf("s3nitor %s starting", Version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down")
		cancel()
	}()

	cfg := config.Load()

	gdb, err := db.NewDB(cfg)
	if err != nil {
		log.Fatalf("failed init DB: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		log.Fatalf("failed migrate DB: %v", err)
	}

	workerCount := cfg.WorkerCount
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	engine := scanner.NewEngine(cfg)

	rep, err := reporter.Build(cfg)
	if err != nil {
		log.Fatalf("failed init reporter: %v", err)
	}

	fetcher, err := s3fetcher.NewS3Fetcher(cfg)
	if err != nil {
		log.Fatalf("failed init s3 fetcher: %v", err)
	}

	objects, err := fetcher.ListObjects(ctx)
	if err != nil {
		log.Fatalf("failed list s3 objects: %v", err)
	}
	log.Printf("listed %d objects", len(objects))

	// Dedup in one query instead of one per object.
	//
	// FileID folds the version into the key, so the mere existence of a record
	// means "this exact content has already been scanned". The old code
	// compared an ETag and a timestamp in the worker and a different timestamp
	// in the upsert, and the two could disagree.
	ids := make([]string, len(objects))
	for i, obj := range objects {
		ids[i] = hashing.FileID(obj.Bucket, obj.Key, obj.ETag)
	}
	seen, err := db.SeenFileIDs(gdb, ids)
	if err != nil {
		log.Fatalf("failed dedup lookup: %v", err)
	}

	type job struct {
		obj    s3fetcher.S3Object
		fileID string
	}
	pending := make([]job, 0, len(objects))
	for i, obj := range objects {
		if seen[ids[i]] {
			continue
		}
		pending = append(pending, job{obj: obj, fileID: ids[i]})
	}
	log.Printf("%d objects to scan, %d skipped as already seen", len(pending), len(objects)-len(pending))

	// Each run gets its own temp directory so a crash leaves an identifiable
	// pile rather than orphans scattered through the system temp dir, and so
	// two objects sharing a basename cannot overwrite each other.
	workDir, err := os.MkdirTemp("", "s3nitor-")
	if err != nil {
		log.Fatalf("failed to create work dir: %v", err)
	}
	defer os.RemoveAll(workDir)

	jobs := make(chan job, len(pending))
	wg := &sync.WaitGroup{}

	// Still one worker pool doing fetch and scan together. Splitting it into
	// resource-shaped stages is the next milestone; this milestone only removes
	// the shared mutable state that would have made that split unsafe.
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
				if err := processOne(ctx, j.obj, j.fileID, workDir, fetcher, engine, rep, gdb); err != nil {
					log.Printf("[worker %d] %s: %v", id, j.obj.Key, err)
				}
			}
		}(i)
	}

	for _, j := range pending {
		jobs <- j
	}
	close(jobs)
	wg.Wait()

	log.Println("done scanning S3 bucket")
}

// processOne downloads, hashes, scans and reports a single object.
func processOne(
	ctx context.Context,
	obj s3fetcher.S3Object,
	fileID, workDir string,
	fetcher *s3fetcher.S3Fetcher,
	engine *scanner.Engine,
	rep reporter.Reporter,
	gdb *gorm.DB,
) error {
	localPath := filepath.Join(workDir, fileID)

	hashes, size, err := download(ctx, fetcher, obj.Key, localPath)
	if err != nil {
		return err
	}
	defer os.Remove(localPath)

	in := &scanner.ScanInput{
		FileID:    fileID,
		Bucket:    obj.Bucket,
		Key:       obj.Key,
		Version:   obj.ETag,
		Size:      size,
		Hashes:    hashes,
		LocalPath: localPath,
	}

	result := engine.ProcessFile(ctx, in)

	// Report before recording the scan. Reversed, a crash in between would
	// leave the object marked as done with its finding never published.
	if err := rep.Report(ctx, result); err != nil {
		return err
	}

	return db.UpsertFileRecord(gdb, &db.FileRecord{
		FileID:       fileID,
		Bucket:       obj.Bucket,
		ObjectKey:    obj.Key,
		Version:      obj.ETag,
		Size:         size,
		MD5:          hashes["md5"],
		SHA1:         hashes["sha1"],
		SHA256:       hashes["sha256"],
		LastModified: obj.LastModified,
		FetchedAt:    time.Now().UTC(),
	})
}

// download streams the object to disk and hashes it on the way through, so the
// bytes are read once rather than once to write and once to hash.
func download(ctx context.Context, fetcher *s3fetcher.S3Fetcher, key, localPath string) (map[string]string, int64, error) {
	body, err := fetcher.Open(ctx, key)
	if err != nil {
		return nil, 0, err
	}
	defer body.Close()

	out, err := os.Create(localPath)
	if err != nil {
		return nil, 0, err
	}
	defer out.Close()

	h := hashing.New()
	if _, err := io.Copy(io.MultiWriter(out, h), body); err != nil {
		return nil, 0, err
	}
	return h.Sum(), h.Size(), nil
}
