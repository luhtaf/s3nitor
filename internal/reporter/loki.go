package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
)

// LokiReporter push ke Loki
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
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (r *LokiReporter) Report(ctx context.Context, data map[string]interface{}) error {
	// Loki expects a specific format
	lokiData := map[string]interface{}{
		"streams": []map[string]interface{}{
			{
				"stream": map[string]string{
					"job": "s3-scanner",
				},
				"values": [][]string{
					{
						fmt.Sprintf("%d", time.Now().UnixNano()),
						fmt.Sprintf("%v", data),
					},
				},
			},
		},
	}

	b, err := json.Marshal(lokiData)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/loki/api/v1/push", r.url)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(b))
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
		return fmt.Errorf("loki error: %s", resp.Status)
	}
	return nil
}
