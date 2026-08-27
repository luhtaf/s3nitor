package reporter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// ReportBatch writes the whole batch in one _bulk request.
//
// Elasticsearch charges per request far more than per document, so a hundred
// individual _doc calls cost roughly a hundred times what one bulk call does.
//
// The document id is derived rather than left to Elasticsearch. At-least-once
// delivery means the same result will occasionally be published twice — after a
// crash between publishing and recording, for instance — and a deterministic id
// turns that replay into an overwrite instead of a duplicate. That property is
// what makes crash recovery correct, not merely tidier.
func (r *ElasticsearchReporter) ReportBatch(ctx context.Context, batch []*scanner.FileResult) error {
	if len(batch) == 0 {
		return nil
	}

	var body bytes.Buffer
	for _, fr := range batch {
		meta := map[string]any{
			"index": map[string]any{
				"_index": r.index,
				"_id":    docID(fr),
			},
		}
		if err := json.NewEncoder(&body).Encode(meta); err != nil {
			return err
		}
		if err := json.NewEncoder(&body).Encode(envelope(fr)); err != nil {
			return err
		}
	}

	endpoint := fmt.Sprintf("%s/_bulk", r.url)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
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

	// A bulk request can return 200 while individual documents failed, so the
	// per-item errors have to be read rather than assumed absent.
	var result struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int             `json:"status"`
			Error  json.RawMessage `json:"error"`
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

// docID is deterministic so a replayed result overwrites itself.
func docID(fr *scanner.FileResult) string {
	sum := sha256.Sum256([]byte(fr.FileID + "\x00" + fr.Version))
	return hex.EncodeToString(sum[:])
}

// envelope builds the document body shared by the single and batch paths.
func envelope(fr *scanner.FileResult) map[string]any {
	return map[string]any{
		"file_id":   fr.FileID,
		"bucket":    fr.Bucket,
		"key":       fr.Key,
		"size":      fr.Size,
		"hashes":    fr.Hashes,
		"scan_time": fr.ScanTime.Format(time.RFC3339),
		"results":   fr.Results,
	}
}
