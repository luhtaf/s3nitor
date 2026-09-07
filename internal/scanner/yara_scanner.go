package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/luhtaf/s3nitor/internal/config"
)

// YARAScanner shells out to the yara binary once per rule file.
//
// It reads the downloaded object, so NeedsPayload is true and a spilled retry
// has to fetch the bytes again.
type YARAScanner struct {
	SyncScanner

	enabled bool
	path    string
	yaraCmd string
	version string
}

// NewYaraScanner self-disables when the binary is missing or the rules
// directory holds no .yar files, so a misconfigured deployment degrades to
// "this scanner is off" rather than failing every object.
func NewYaraScanner(cfg *config.Config) *YARAScanner {
	y := &YARAScanner{
		SyncScanner: SyncScanner{ScanTimeout: cfg.ScanTimeout},
		enabled:     cfg.EnableYara,
		path:        "rules/yara/",
		yaraCmd:     cfg.YARACmd,
	}
	if cfg.YARAPath != "" {
		y.path = cfg.YARAPath
	}
	if !y.enabled {
		log.Println("YARAScanner: disabled via config")
		return y
	}

	if _, err := exec.LookPath(y.yaraCmd); err != nil {
		log.Printf("YARAScanner: yara executable not found in PATH: %v", err)
		y.enabled = false
		return y
	}

	files, err := y.ruleFiles()
	if err != nil {
		log.Printf("YARAScanner: error listing yara files: %v", err)
		y.enabled = false
		return y
	}
	if len(files) == 0 {
		log.Printf("YARAScanner: no .yar files found in %s", y.path)
		y.enabled = false
		return y
	}

	y.version = y.computeVersion(files)
	log.Printf("YARAScanner: found %d yara files in %s", len(files), y.path)
	return y
}

func (y *YARAScanner) Name() string         { return "yara" }
func (y *YARAScanner) Enabled() bool        { return y.enabled }
func (y *YARAScanner) NeedsPayload() bool   { return true }
func (y *YARAScanner) RulesVersion() string { return y.version }

// Scan runs every rule file over the object and collects the rule names that fired.
func (y *YARAScanner) Scan(ctx context.Context, in *ScanInput) (Result, error) {
	if in.LocalPath == "" {
		return Result{}, fmt.Errorf("yara: needs the payload but LocalPath is empty")
	}

	ruleFiles, err := y.ruleFiles()
	if err != nil {
		return Result{}, fmt.Errorf("yara: listing rules: %w", err)
	}
	if len(ruleFiles) == 0 {
		return Result{}, fmt.Errorf("yara: no rule files in %s", y.path)
	}

	var matches []string
	for _, ruleFile := range ruleFiles {
		out, err := exec.CommandContext(ctx, y.yaraCmd, ruleFile, in.LocalPath).Output()
		if err != nil {
			// yara exits 1 to mean "no rule matched", which is an ordinary
			// result rather than a failure.
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				continue
			}
			log.Printf("YARAScanner: error running yara on %s: %v", ruleFile, err)
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if fields := strings.Fields(strings.TrimSpace(line)); len(fields) > 0 {
				matches = append(matches, fields[0])
			}
		}
	}
	sort.Strings(matches)

	res := Result{
		Match:    len(matches) > 0,
		Severity: SeverityInfo,
		Detail: map[string]any{
			"rules":      matches,
			"rule_files": len(ruleFiles),
		},
	}
	if res.Match {
		// A pattern hit is weaker evidence than an exact hash hit: rules vary
		// in precision and false positives are ordinary.
		res.Severity = SeverityMedium
	}
	return res, nil
}

// ruleFiles globs the rules directory. Only .yar is matched — .yara files are
// not picked up.
func (y *YARAScanner) ruleFiles() ([]string, error) {
	return filepath.Glob(filepath.Join(y.path, "*.yar"))
}

// computeVersion fingerprints the rule files so editing a rule reschedules only
// the yara tasks.
func (y *YARAScanner) computeVersion(files []string) string {
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			log.Printf("YARAScanner: cannot read %s for versioning: %v", f, err)
			continue
		}
		h.Write([]byte(filepath.Base(f)))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
