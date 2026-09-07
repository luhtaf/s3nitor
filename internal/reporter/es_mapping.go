package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// indexTemplate defines the shape of a findings index.
//
// Without it Elasticsearch infers the mapping from the first document, and its
// guesses are wrong in two ways that matter.
//
// First, every string becomes `text`, which cannot be aggregated or sorted — so
// "count by severity" and "sort by key" both fail with "Fielddata is disabled".
// These fields are identifiers and enumerations, never prose, so `keyword` is
// what they are.
//
// Second, `detail` carries whatever each scanner chooses to report. Under
// dynamic mapping every key any scanner ever emits becomes an indexed field,
// the mapping grows without bound, and the first time two scanners use the same
// key with different types Elasticsearch rejects the document outright.
// Disabling it keeps the content in _source — the dashboard still shows it —
// while indexing none of it.
var indexTemplate = map[string]any{
	"index_patterns": []string{"PLACEHOLDER"},
	"priority":       100,
	"template": map[string]any{
		"settings": map[string]any{
			"number_of_shards":   1,
			"number_of_replicas": 0,
		},
		"mappings": map[string]any{
			"dynamic": "strict",
			"properties": map[string]any{
				"file_id":       map[string]any{"type": "keyword"},
				"bucket":        map[string]any{"type": "keyword"},
				"key":           map[string]any{"type": "keyword", "ignore_above": 2048},
				"version":       map[string]any{"type": "keyword"},
				"size":          map[string]any{"type": "long"},
				"scanner":       map[string]any{"type": "keyword"},
				"rules_version": map[string]any{"type": "keyword"},
				"match":         map[string]any{"type": "boolean"},
				"severity":      map[string]any{"type": "keyword"},
				"scanned_at":    map[string]any{"type": "date"},
				"error":         map[string]any{"type": "text"},
				"hashes": map[string]any{
					"properties": map[string]any{
						"md5":    map[string]any{"type": "keyword"},
						"sha1":   map[string]any{"type": "keyword"},
						"sha256": map[string]any{"type": "keyword"},
					},
				},
				// Stored, searchable via _source, deliberately not indexed.
				"detail": map[string]any{"type": "object", "enabled": false},
			},
		},
	},
}

// EnsureTemplate installs the index template if it is absent.
//
// Idempotent and best-effort: a scanner that cannot manage templates — a
// read-restricted API key, say — should still be able to write findings, so a
// failure here is logged rather than fatal. It only affects indices created
// afterwards; an index that already exists keeps whatever mapping it was born
// with, and fixing that needs a reindex.
func (r *ElasticsearchReporter) EnsureTemplate(ctx context.Context) error {
	name := "s3nitor-findings"

	tmpl := make(map[string]any, len(indexTemplate))
	for k, v := range indexTemplate {
		tmpl[k] = v
	}
	tmpl["index_patterns"] = []string{r.index, r.index + "-*"}

	b, err := json.Marshal(tmpl)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("%s/_index_template/%s", r.url, name), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.authorize(req)

	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("installing index template: %s: %s", resp.Status, snippet(resp))
	}
	log.Printf("elasticsearch: index template %q ensured for %q", name, r.index)
	return nil
}
