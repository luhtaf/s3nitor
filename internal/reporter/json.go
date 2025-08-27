package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// JSONReporter output ke stdout atau file
type JSONReporter struct {
	outputFile string
}

func NewJSONReporter(cfg *config.Config) (*JSONReporter, error) {
	return &JSONReporter{outputFile: cfg.ReporterPath}, nil
}

func (r *JSONReporter) Report(ctx context.Context, sc *scanner.ScanContext) error {
	// Create enriched data with metadata
	enrichedData := map[string]interface{}{
		"bucket":    sc.Bucket,
		"key":       sc.Key,
		"size":      sc.Size,
		"hashes":    sc.Hashes,
		"scan_time": time.Now().Format(time.RFC3339),
		"results":   sc.Results,
	}

	b, err := json.MarshalIndent(enrichedData, "", "  ")
	if err != nil {
		return err
	}

	if r.outputFile == "" {
		// stdout
		fmt.Println(string(b))
		return nil
	}

	// simpan ke file
	f, err := os.OpenFile(r.outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(b, '\n'))
	return err
}
