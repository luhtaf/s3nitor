package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// IOCScanner memeriksa hash file terhadap IOC (md5, sha1, sha256)
type IOCScanner struct {
	md5Set    map[string]bool
	sha1Set   map[string]bool
	sha256Set map[string]bool
	enabled   bool
	path      string
}

// NewIOCScanner inisialisasi scanner dengan Config
func NewIOCScanner(cfg *Config) *IOCScanner {
	i := &IOCScanner{
		md5Set:    make(map[string]bool),
		sha1Set:   make(map[string]bool),
		sha256Set: make(map[string]bool),
		enabled:   cfg.EnableIOC,
		path:      cfg.IOCPath,
	}

	if !i.enabled {
		log.Println("IOCScanner: disabled via config")
		return i
	}

	if i.path == "" {
		i.path = "rules/ioc/"
	}

	// load IOC files
	i.loadFile(filepath.Join(i.path, "md5.txt"), i.md5Set)
	i.loadFile(filepath.Join(i.path, "sha1.txt"), i.sha1Set)
	i.loadFile(filepath.Join(i.path, "sha256.txt"), i.sha256Set)

	return i
}

// Name nama scanner
func (i *IOCScanner) Name() string { return "ioc_scanner" }

// Enabled cek scanner aktif
func (i *IOCScanner) Enabled() bool { return i.enabled }

// Scan per file
func (i *IOCScanner) Scan(ctx context.Context, sc *ScanContext) (map[string]interface{}, error) {
	if sc.Hashes == nil || (sc.Hashes["md5"] == "" && sc.Hashes["sha1"] == "" && sc.Hashes["sha256"] == "") {
		return nil, fmt.Errorf("IOCScanner: no hash data in ScanContext")
	}

	matches := []string{}
	if i.md5Set[sc.Hashes["md5"]] {
		matches = append(matches, "md5")
	}
	if i.sha1Set[sc.Hashes["sha1"]] {
		matches = append(matches, "sha1")
	}
	if i.sha256Set[sc.Hashes["sha256"]] {
		matches = append(matches, "sha256")
	}

	results := map[string]interface{}{
		"ioc_match": len(matches) > 0,
		"ioc_types": matches,
	}

	// simpan ke ScanContext
	sc.Results[i.Name()] = results
	return results, nil
}

// loadFile baca IOC file ke map
func (i *IOCScanner) loadFile(filename string, target map[string]bool) {
	f, err := os.Open(filename)
	if err != nil {
		log.Printf("IOCScanner: file %s not found, skipping", filename)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			target[line] = true
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("IOCScanner: error reading %s: %v", filename, err)
	}
	log.Printf("IOCScanner: loaded %d entries from %s", count, filename)
}
