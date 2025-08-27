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
	case "prometheus":
		return NewPrometheusReporter(cfg)
	case "":
		// default fallback → JSON stdout
		return NewJSONReporter(cfg)
	default:
		return nil, fmt.Errorf("unknown reporter type: %s", cfg.ReporterType)
	}
}
