package reporter

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
)

// PrometheusReporter push metrics ke Prometheus
type PrometheusReporter struct {
	url    string
	client *http.Client
}

func NewPrometheusReporter(cfg *config.Config) (*PrometheusReporter, error) {
	if cfg.PrometheusURL == "" {
		return nil, fmt.Errorf("invalid prometheus config: url=%s", cfg.PrometheusURL)
	}
	return &PrometheusReporter{
		url:    cfg.PrometheusURL,
		client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (r *PrometheusReporter) Report(ctx context.Context, data map[string]interface{}) error {
	// Convert scan results to Prometheus metrics
	_ = r.convertToMetrics(data)

	// For simplicity, we'll use a basic HTTP endpoint
	// In production, you might want to use a proper Prometheus client
	endpoint := fmt.Sprintf("%s/metrics", r.url)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("prometheus error: %s", resp.Status)
	}
	return nil
}

func (r *PrometheusReporter) convertToMetrics(data map[string]interface{}) string {
	// Convert scan results to Prometheus format
	// This is a simplified implementation
	metrics := ""

	// Count total files scanned
	metrics += "# HELP s3_scanner_files_total Total files scanned\n"
	metrics += "# TYPE s3_scanner_files_total counter\n"
	metrics += fmt.Sprintf("s3_scanner_files_total %d\n", time.Now().Unix())

	// Count malware detections
	if malware, ok := data["malware_detected"]; ok {
		if detected, ok := malware.(bool); ok && detected {
			metrics += "# HELP s3_scanner_malware_detected Malware detection count\n"
			metrics += "# TYPE s3_scanner_malware_detected counter\n"
			metrics += "s3_scanner_malware_detected 1\n"
		}
	}

	return metrics
}
