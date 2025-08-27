package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// OTXScanner cek file hash via AlienVault OTX API
type OTXScanner struct {
	enabled bool
	apiKey  string
	client  *http.Client
}

// NewOTXScanner inisialisasi scanner dengan Config
func NewOTXScanner(cfg *Config) *OTXScanner {
	return &OTXScanner{
		enabled: cfg.EnableOTX && cfg.S3Endpoint != "",
		apiKey:  cfg.OTXAPIKey, // tambahkan field OTXAPIKey di Config
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (o *OTXScanner) Name() string  { return "otx_scanner" }
func (o *OTXScanner) Enabled() bool { return o.enabled && o.apiKey != "" }

// Scan file via OTX API (hash dari ScanContext)
func (o *OTXScanner) Scan(ctx context.Context, sc *ScanContext) (map[string]interface{}, error) {
	sha256 := sc.Hashes["sha256"]
	if sha256 == "" {
		return nil, fmt.Errorf("OTXScanner: no SHA256 hash in ScanContext")
	}

	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/file/%s", sha256)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		log.Printf("[%s] error: %v", o.Name(), err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OTXScanner: status code %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	results := map[string]interface{}{
		"otx_match": len(data) > 0,
		"otx_data":  data,
	}

	sc.Results[o.Name()] = results
	return results, nil
}
