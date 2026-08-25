package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
)

// OTXScanner asks AlienVault OTX what it knows about an object's SHA256.
//
// Hash-only, so NeedsPayload is false: a retry costs one HTTP call and never a
// re-download.
type OTXScanner struct {
	enabled bool
	apiKey  string
	client  *http.Client
}

func NewOTXScanner(cfg *config.Config) *OTXScanner {
	return &OTXScanner{
		enabled: cfg.EnableOTX,
		apiKey:  cfg.OTXAPIKey,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (o *OTXScanner) Name() string       { return "otx" }
func (o *OTXScanner) Enabled() bool      { return o.enabled && o.apiKey != "" }
func (o *OTXScanner) NeedsPayload() bool { return false }

// RulesVersion is fixed: the verdict depends on OTX's data rather than on any
// ruleset held here, so there is no local version to invalidate against.
func (o *OTXScanner) RulesVersion() string { return "otx-v1" }

func (o *OTXScanner) Scan(ctx context.Context, in *ScanInput) (Result, error) {
	sha256sum := in.Hashes["sha256"]
	if sha256sum == "" {
		return Result{}, fmt.Errorf("otx: no sha256 in ScanInput")
	}

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/file/%s", sha256sum)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("X-OTX-API-KEY", o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("otx: %w", err)
	}
	defer resp.Body.Close()

	// 404 means OTX has never seen this hash. That is an answer, not a failure:
	// treating it as an error would retry the lookup forever and burn quota.
	if resp.StatusCode == http.StatusNotFound {
		return Result{
			Severity: SeverityInfo,
			Detail:   map[string]any{"known": false},
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("otx: status %d", resp.StatusCode)
	}

	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return Result{}, fmt.Errorf("otx: decoding response: %w", err)
	}

	pulses := 0
	if info, ok := data["pulse_info"].(map[string]any); ok {
		if n, ok := info["count"].(float64); ok {
			pulses = int(n)
		}
	}

	res := Result{
		Match:    pulses > 0,
		Severity: SeverityInfo,
		Detail:   map[string]any{"known": true, "pulse_count": pulses},
	}
	if res.Match {
		// Third-party intel corroborates; it does not convict on its own.
		res.Severity = SeverityMedium
	}
	return res, nil
}
