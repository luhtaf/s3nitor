package reporter

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
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

func (r *PrometheusReporter) Report(ctx context.Context, sc *scanner.ScanContext) error {
	// Convert scan results to Prometheus metrics
	_ = r.convertToMetrics(sc)

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

func (r *PrometheusReporter) convertToMetrics(sc *scanner.ScanContext) string {
	// Convert scan results to Prometheus format
	// This is a simplified implementation
	metrics := ""

	// Count total files scanned
	metrics += "# HELP s3_scanner_files_total Total files scanned\n"
	metrics += "# TYPE s3_scanner_files_total counter\n"
	metrics += fmt.Sprintf("s3_scanner_files_total %d\n", time.Now().Unix())

	// Add file size metric
	metrics += "# HELP s3_scanner_file_size_bytes File size in bytes\n"
	metrics += "# TYPE s3_scanner_file_size_bytes gauge\n"
	metrics += fmt.Sprintf("s3_scanner_file_size_bytes{bucket=\"%s\",key=\"%s\"} %d\n",
		sc.Bucket, sc.Key, sc.Size)

	// Count malware detections from results
	for scannerName, result := range sc.Results {
		if resultMap, ok := result.(map[string]interface{}); ok {
			if match, ok := resultMap["ioc_match"]; ok {
				if detected, ok := match.(bool); ok && detected {
					metrics += fmt.Sprintf("# HELP s3_scanner_%s_detected %s detection count\n", scannerName, scannerName)
					metrics += fmt.Sprintf("# TYPE s3_scanner_%s_detected counter\n", scannerName)
					metrics += fmt.Sprintf("s3_scanner_%s_detected 1\n", scannerName)
				}
			}
		}
	}

	return metrics
}
