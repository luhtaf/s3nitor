package scanner

import (
	"context"
	"log"

	"github.com/luhtaf/s3nitor/internal/config"
)

// Scanner interface → semua scanner wajib implementasi ini
type Scanner interface {
	Name() string
	Scan(ctx context.Context, sc *ScanContext) error
	Enabled() bool
}

// Engine → orchestrator untuk semua scanner
type Engine struct {
	scanners []Scanner
}

// ScanContext → data yang dishare antar scanner
type ScanContext struct {
	FilePath string
	Hashes   map[string]string      // md5, sha1, sha256
	Results  map[string]interface{} // hasil semua scanner
}

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

// ProcessFile → scan 1 file lewat semua scanner
func (e *Engine) ProcessFile(ctx context.Context, filePath string) error {
	sc := &ScanContext{
		FilePath: filePath,
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

	// setelah semua scanner jalan → output
	if err := WriteOutput(sc); err != nil {
		return err
	}

	return nil
}
