package reporter

import (
	"fmt"

	"github.com/luhtaf/s3nitor/internal/config"
)

// Build memilih reporter berdasarkan config
func Build(cfg *config.Config) (Reporter, error) {
	switch cfg.ReporterType {
	case "json":
		return NewJSONReporter(cfg)
	case "elasticsearch":
		return NewElasticsearchReporter(cfg)
	case "loki":
		return NewLokiReporter(cfg)
	case "":
		// default fallback → JSON stdout
		return NewJSONReporter(cfg)
	case "prometheus":
		// Removed rather than kept: Prometheus scrapes, so a reporter that
		// pushes to it never worked. Pipeline metrics are served from
		// internal/metrics on METRICS_ADDR instead.
		return nil, fmt.Errorf("REPORTER_TYPE=prometheus is not a thing: Prometheus scrapes. " +
			"Metrics are served on METRICS_ADDR; pick json, elasticsearch or loki for findings")
	default:
		return nil, fmt.Errorf("unknown reporter type: %s", cfg.ReporterType)
	}
}
