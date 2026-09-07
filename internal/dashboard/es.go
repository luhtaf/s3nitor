// Package dashboard serves a read-only view of what the scanner found.
//
// A separate binary from the scanner, and read-only by construction: it issues
// searches and aggregations, never writes, and never exposes a path that could.
// The Elasticsearch credentials stay here rather than in the browser — the
// cluster user is a superuser, and shipping it to every visitor would hand out
// full control of the cluster along with the dashboard.
package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ES is a minimal read-only Elasticsearch client.
type ES struct {
	url      string
	index    string
	username string
	password string
	apiKey   string
	http     *http.Client
}

// NewES builds the client. Nothing is verified here — an unreachable cluster
// should surface as a visible error in the UI rather than as a process that
// refuses to start.
func NewES(url, index, username, password, apiKey string) *ES {
	return &ES{
		url:      strings.TrimRight(url, "/"),
		index:    index,
		username: username,
		password: password,
		apiKey:   apiKey,
		http:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (e *ES) search(ctx context.Context, body map[string]any) (map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/%s/_search", e.url, e.index), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case e.apiKey != "":
		req.Header.Set("Authorization", "ApiKey "+e.apiKey)
	case e.username != "":
		req.SetBasicAuth(e.username, e.password)
	}

	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// An index that does not exist yet is not an error worth shouting about:
	// it just means nothing has been scanned. The UI shows an empty state.
	if resp.StatusCode == http.StatusNotFound {
		return map[string]any{}, nil
	}
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return nil, fmt.Errorf("elasticsearch %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// filters describes what the caller wants to see.
type filters struct {
	Query    string
	Scanner  string
	Severity string
	Match    string // "", "true", "false"
	Since    string // an Elasticsearch date-math expression, e.g. "now-7d"
}

// query builds the bool query shared by every endpoint, so a filter set means
// the same thing on the table, the charts and the coverage view.
func (f filters) query() map[string]any {
	must := []any{}
	filter := []any{}

	if f.Query != "" {
		// wildcard on key rather than a match query: object keys are paths, not
		// prose, and an analyzer would split them on punctuation and return
		// surprising results.
		must = append(must, map[string]any{
			"wildcard": map[string]any{
				"key": map[string]any{"value": "*" + f.Query + "*", "case_insensitive": true},
			},
		})
	}
	for field, value := range map[string]string{
		"scanner": f.Scanner, "severity": f.Severity,
	} {
		if value != "" {
			filter = append(filter, map[string]any{"term": map[string]any{field: value}})
		}
	}
	if f.Match == "true" || f.Match == "false" {
		filter = append(filter, map[string]any{"term": map[string]any{"match": f.Match == "true"}})
	}
	if f.Since != "" {
		filter = append(filter, map[string]any{
			"range": map[string]any{"scanned_at": map[string]any{"gte": f.Since}},
		})
	}

	if len(must) == 0 && len(filter) == 0 {
		return map[string]any{"match_all": map[string]any{}}
	}
	return map[string]any{"bool": map[string]any{"must": must, "filter": filter}}
}

func num(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

// dig walks nested maps, returning nil rather than panicking on a shape that
// does not match — an aggregation is absent whenever the index is empty.
func dig(m map[string]any, path ...string) any {
	var cur any = m
	for _, p := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = asMap[p]
	}
	return cur
}

func buckets(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
