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

// LokiReporter pushes findings as log lines.
type LokiReporter struct {
	url    string
	client *http.Client
}

func NewLokiReporter(cfg *config.Config) (*LokiReporter, error) {
	if cfg.LokiURL == "" {
		return nil, fmt.Errorf("invalid loki config: url=%s", cfg.LokiURL)
	}
	return &LokiReporter{
		url:    cfg.LokiURL,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (r *LokiReporter) Report(ctx context.Context, f *scanner.Finding) error {
	line, err := json.Marshal(f)
	if err != nil {
		return err
	}

	// Scanner and severity become stream labels so Loki can select on them
	// without parsing the line; everything else stays in the body, since a label
	// per file id would blow up the index cardinality.
	payload := map[string]any{
		"streams": []map[string]any{{
			"stream": map[string]string{
				"job":      "s3nitor",
				"scanner":  f.Scanner,
				"severity": string(f.Severity),
			},
			"values": [][]string{{
				fmt.Sprintf("%d", f.ScannedAt.UnixNano()),
				string(line),
			}},
		}},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/loki/api/v1/push", r.url), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("loki: %s", resp.Status)
	}
	return nil
}
