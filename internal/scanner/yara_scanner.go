package scanner

import (
	"context"
	"log"
	"path/filepath"

	"github.com/hillu/go-yara/v4"
)

type YARAScanner struct {
	rules   *yara.Rules
	enabled bool
	path    string
}

func NewYARAScanner(cfg *Config) *YARAScanner {
	y := &YARAScanner{
		enabled: cfg.EnableYara,
		path:    "rules/yara/",
	}

	if cfg.YARAPath != "" {
		y.path = cfg.YARAPath
	}

	if !y.enabled {
		log.Println("YARAScanner: disabled via config")
		return y
	}

	compiler, err := yara.NewCompiler()
	if err != nil {
		log.Printf("YARAScanner: failed to init compiler: %v", err)
		y.enabled = false
		return y
	}

	files, err := filepath.Glob(filepath.Join(y.path, "*.yar"))
	if err != nil {
		log.Printf("YARAScanner: error listing yara files: %v", err)
		y.enabled = false
		return y
	}

	for _, f := range files {
		if err := compiler.AddFile(f, ""); err != nil {
			log.Printf("YARAScanner: error compiling %s: %v", f, err)
		}
	}

	y.rules, err = compiler.GetRules()
	if err != nil {
		log.Printf("YARAScanner: failed to get compiled rules: %v", err)
		y.enabled = false
	}

	log.Printf("YARAScanner: loaded %d rules from %s", len(files), y.path)
	return y
}

func (y *YARAScanner) Name() string  { return "yara_scanner" }
func (y *YARAScanner) Enabled() bool { return y.enabled }

func (y *YARAScanner) Scan(ctx context.Context, sc *ScanContext) (map[string]interface{}, error) {
	if !y.enabled || sc.FilePath == "" {
		return nil, nil
	}

	matches := []string{}
	err := y.rules.ScanFile(sc.FilePath, 0, func(rule *yara.MatchRule) error {
		matches = append(matches, rule.Identifier)
		return nil
	})
	if err != nil {
		log.Printf("YARAScanner: error scanning %s: %v", sc.FilePath, err)
		return nil, err
	}

	results := map[string]interface{}{
		"yara_match": len(matches) > 0,
		"yara_rules": matches,
	}

	sc.Results[y.Name()] = results
	return results, nil
}
