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

// ElasticsearchReporter indexes findings, one document each.
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
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Report indexes a single finding under its deterministic id, so a replayed
// result overwrites itself instead of duplicating.
func (r *ElasticsearchReporter) Report(ctx context.Context, f *scanner.Finding) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/%s/_doc/%s", r.url, r.index, f.DocID())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(b))
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
		return fmt.Errorf("elasticsearch: %s", resp.Status)
	}
	return nil
}

// ReportBatch writes the whole batch in one _bulk request.
//
// Elasticsearch charges far more per request than per document, so a hundred
// individual calls cost roughly a hundred times what one bulk call does.
func (r *ElasticsearchReporter) ReportBatch(ctx context.Context, batch []*scanner.Finding) error {
	if len(batch) == 0 {
		return nil
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, f := range batch {
		meta := map[string]any{
			"index": map[string]any{"_index": r.index, "_id": f.DocID()},
		}
		if err := enc.Encode(meta); err != nil {
			return err
		}
		if err := enc.Encode(f); err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/_bulk", r.url), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("elasticsearch bulk: %s", resp.Status)
	}

	// A bulk request returns 200 even when individual documents failed, so the
	// per-item statuses have to be read rather than assumed clean.
	var result struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Error json.RawMessage `json:"error"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("elasticsearch bulk: decoding response: %w", err)
	}
	if result.Errors {
		for _, item := range result.Items {
			for _, detail := range item {
				if detail.Error != nil {
					return fmt.Errorf("elasticsearch bulk: %s", detail.Error)
				}
			}
		}
	}
	return nil
}
