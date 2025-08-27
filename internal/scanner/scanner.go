package scanner

import (
	"context"
	"log"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/s3fetcher"
)

// NewEngine build engine & register scanner sesuai config
func NewEngine(cfg *config.Config) *Engine {
	e := &Engine{}

	// always enable hash scanner (fondasi buat IOC/OTX)
	e.scanners = append(e.scanners, NewHashScanner())

	if cfg.EnableIOC {
		e.scanners = append(e.scanners, NewIOCScanner(cfg))
	}
	if cfg.EnableOTX {
		e.scanners = append(e.scanners, NewOTXScanner(cfg))
	}
	if cfg.EnableYara {
		e.scanners = append(e.scanners, NewYaraScanner(cfg))
	}

	return e
}

// Run (dipanggil dari main) → disini bakal dihandle di luar (misal loop S3 files)
// Engine cukup siap untuk ProcessFile()
func (e *Engine) Run(ctx context.Context) error {
	log.Println("Engine ready, waiting for files to scan...")
	<-ctx.Done()
	return nil
}

func (e *Engine) ProcessFile(ctx context.Context, obj s3fetcher.S3Object, localPath string) (*ScanContext, error) {
	sc := &ScanContext{
		Bucket:   obj.Bucket,
		Key:      obj.Key,
		Size:     obj.Size,
		FilePath: localPath,
		Results:  make(map[string]interface{}),
	}

	for _, s := range e.scanners {
		if !s.Enabled() {
			continue
		}
		if err := s.Scan(ctx, sc); err != nil {
			log.Printf("[%s] error: %v", s.Name(), err)
		}
	}

	return sc, nil
}
