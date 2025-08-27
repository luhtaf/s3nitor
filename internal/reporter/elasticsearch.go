package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/luhtaf/s3nitor/internal/config"
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

func (r *ElasticsearchReporter) Report(ctx context.Context, data map[string]interface{}) error {
	b, err := json.Marshal(data)
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
