package scanner

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/luhtaf/s3nitor/internal/config"
)

type YARAScanner struct {
	enabled bool
	path    string
	yaraCmd string
}

func NewYaraScanner(cfg *config.Config) *YARAScanner {
	y := &YARAScanner{
		enabled: cfg.EnableYara,
		path:    "rules/yara/",
		yaraCmd: cfg.YARACmd,
	}

	if cfg.YARAPath != "" {
		y.path = cfg.YARAPath
	}

	if !y.enabled {
		log.Println("YARAScanner: disabled via config")
		return y
	}

	// Check if yara executable is available
	if _, err := exec.LookPath(y.yaraCmd); err != nil {
		log.Printf("YARAScanner: yara executable not found in PATH: %v", err)
		y.enabled = false
		return y
	}

	// Check if rules directory exists and has .yar files
	files, err := filepath.Glob(filepath.Join(y.path, "*.yar"))
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

	log.Printf("YARAScanner: found %d yara files in %s", len(files), y.path)
	return y
}

func (y *YARAScanner) Name() string  { return "yara_scanner" }
func (y *YARAScanner) Enabled() bool { return y.enabled }

func (y *YARAScanner) Scan(ctx context.Context, sc *ScanContext) error {
	if !y.enabled || sc.FilePath == "" {
		return nil
	}

	// Get all .yar files in the rules directory
	ruleFiles, err := filepath.Glob(filepath.Join(y.path, "*.yar"))
	if err != nil {
		return fmt.Errorf("error listing yara files: %v", err)
	}

	if len(ruleFiles) == 0 {
		return fmt.Errorf("no yara rule files found in %s", y.path)
	}

	matches := []string{}

	// Run yara command for each rule file
	for _, ruleFile := range ruleFiles {
		cmd := exec.CommandContext(ctx, y.yaraCmd, ruleFile, sc.FilePath)
		output, err := cmd.Output()

		if err != nil {
			// If yara returns non-zero exit code, it might mean no matches found
			// This is not necessarily an error
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				// No matches found, this is normal
				continue
			}
			log.Printf("YARAScanner: error running yara on %s: %v", ruleFile, err)
			continue
		}

		// Parse output - yara outputs "rule_name file_path" for each match
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				// Extract rule name (first part before space)
				parts := strings.Fields(line)
				if len(parts) > 0 {
					ruleName := parts[0]
					matches = append(matches, ruleName)
				}
			}
		}
	}

	results := map[string]interface{}{
		"yara_match": len(matches) > 0,
		"yara_rules": matches,
		"rule_files": len(ruleFiles),
	}

	sc.Results[y.Name()] = results
	return nil
}
