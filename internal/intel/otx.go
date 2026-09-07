package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// otx queries AlienVault OTX.
type otx struct{ apiKey string }

func (o *otx) name() string { return "otx" }

func (o *otx) request(ctx context.Context, sha256 string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://otx.alienvault.com/api/v1/indicators/file/"+sha256, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", o.apiKey)
	return req, nil
}

// parse reads the pulse count: OTX groups indicators into "pulses", and how many
// reference a hash is the closest thing it offers to a verdict.
func (o *otx) parse(body []byte) (scanner.Result, error) {
	var data struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return scanner.Result{}, err
	}

	res := scanner.Result{
		Match:    data.PulseInfo.Count > 0,
		Severity: scanner.SeverityInfo,
		Detail:   map[string]any{"known": true, "pulse_count": data.PulseInfo.Count},
	}
	if res.Match {
		// Corroboration, not a conviction: a pulse means somebody catalogued
		// this hash, not that this file is malicious.
		res.Severity = scanner.SeverityMedium
	}
	return res, nil
}

// NewOTX builds the OTX scanner. It reports disabled without an API key rather
// than failing every object.
func NewOTX(cfg *config.Config, gdb *gorm.DB) scanner.Scanner {
	return &lookup{
		SyncScanner: scanner.SyncScanner{ScanTimeout: cfg.ScanTimeout},
		p:           &otx{apiKey: cfg.OTXAPIKey},
		gdb:         gdb,
		client:      &http.Client{Timeout: 15 * time.Second},
		enabled:     cfg.EnableOTX && cfg.OTXAPIKey != "",
		cacheTTL:    cfg.IntelCacheTTL,
	}
}
