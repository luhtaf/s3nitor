package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// ElasticsearchReporter push ke Elasticsearch
type ElasticsearchReporter struct {
	url   string
	index string
	http  *http.Client
}

func NewElasticsearchReporter(cfg *config.Config) (*ElasticsearchReporter, error) {
	if cfg.ESUrl == "" || cfg.ESIndex == "" {
		return nil, fmt.Errorf("invalid elasticsearch config: url=%s index=%s", cfg.ESUrl, cfg.ESIndex)
	}
	return &ElasticsearchReporter{
		url:   cfg.ESUrl,
		index: cfg.ESIndex,
		http:  &http.Client{},
	}, nil
}

func (r *ElasticsearchReporter) Report(ctx context.Context, fr *scanner.FileResult) error {
	// Create enriched data with metadata
	enrichedData := map[string]interface{}{
		"bucket":    fr.Bucket,
		"key":       fr.Key,
		"size":      fr.Size,
		"hashes":    fr.Hashes,
		"scan_time": fr.ScanTime.Format(time.RFC3339),
		"results":   fr.Results,
	}

	b, err := json.Marshal(enrichedData)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/%s/_doc", r.url, r.index)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("elasticsearch error: %s", resp.Status)
	}
	return nil
}
