package scanner

import (
	"context"
)

// Engine → orchestrator untuk semua scanner
type Engine struct {
	scanners []Scanner
}

// ScanContext adalah konteks hasil unduhan file yang bisa dipakai semua scanner
type ScanContext struct {
	Bucket   string
	Key      string
	Size     int64
	Hashes   map[string]string      // md5, sha1, sha256, dll
	FilePath string                 // path file sementara (kalau butuh akses fisik)
	Results  map[string]interface{} // hasil semua scanner
}

// Scanner interface
type Scanner interface {
	Name() string
	Enabled() bool
	Scan(ctx context.Context, sc *ScanContext) error
}
