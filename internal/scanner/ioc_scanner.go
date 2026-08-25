package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luhtaf/s3nitor/internal/config"
)

// IOCScanner checks an object's hashes against known-bad lists loaded from disk.
//
// It reads only ScanInput.Hashes, so it never touches the downloaded file and a
// retry never has to fetch the object again.
type IOCScanner struct {
	md5Set    map[string]bool
	sha1Set   map[string]bool
	sha256Set map[string]bool
	enabled   bool
	path      string
	version   string
}

// NewIOCScanner loads the IOC lists once at startup. Missing files are skipped
// with a log line rather than treated as fatal.
func NewIOCScanner(cfg *config.Config) *IOCScanner {
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

	i.loadFile(filepath.Join(i.path, "md5.txt"), i.md5Set)
	i.loadFile(filepath.Join(i.path, "sha1.txt"), i.sha1Set)
	i.loadFile(filepath.Join(i.path, "sha256.txt"), i.sha256Set)
	i.version = i.computeVersion()

	return i
}

func (i *IOCScanner) Name() string         { return "ioc" }
func (i *IOCScanner) Enabled() bool        { return i.enabled }
func (i *IOCScanner) NeedsPayload() bool   { return false }
func (i *IOCScanner) RulesVersion() string { return i.version }

// Scan reports whether any of the object's hashes appears in the loaded lists.
func (i *IOCScanner) Scan(ctx context.Context, in *ScanInput) (Result, error) {
	if len(in.Hashes) == 0 {
		return Result{}, fmt.Errorf("ioc: no hashes in ScanInput")
	}

	var matched []string
	for algo, set := range map[string]map[string]bool{
		"md5": i.md5Set, "sha1": i.sha1Set, "sha256": i.sha256Set,
	} {
		if h := in.Hashes[algo]; h != "" && set[h] {
			matched = append(matched, algo)
		}
	}
	sort.Strings(matched)

	res := Result{
		Match:    len(matched) > 0,
		Severity: SeverityInfo,
		Detail:   map[string]any{"matched_on": matched},
	}
	if res.Match {
		// An exact hash hit against a curated list is about as unambiguous as
		// this tool gets, so it outranks a pattern match.
		res.Severity = SeverityHigh
	}
	return res, nil
}

// loadFile reads one hash per line into target.
func (i *IOCScanner) loadFile(filename string, target map[string]bool) {
	f, err := os.Open(filename)
	if err != nil {
		log.Printf("IOCScanner: file %s not found, skipping", filename)
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line != "" && !strings.HasPrefix(line, "#") {
			target[line] = true
			count++
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("IOCScanner: error reading %s: %v", filename, err)
	}
	log.Printf("IOCScanner: loaded %d entries from %s", count, filename)
}

// computeVersion fingerprints the loaded set so that editing a list invalidates
// this scanner's prior results — and only this scanner's.
func (i *IOCScanner) computeVersion() string {
	all := make([]string, 0, len(i.md5Set)+len(i.sha1Set)+len(i.sha256Set))
	for _, set := range []map[string]bool{i.md5Set, i.sha1Set, i.sha256Set} {
		for h := range set {
			all = append(all, h)
		}
	}
	sort.Strings(all) // map iteration order is random; the fingerprint must not be
	sum := sha256.Sum256([]byte(strings.Join(all, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}
