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

// virustotal looks a hash up in VirusTotal.
//
// Hash lookup only. There is no upload path and deliberately no setting to
// enable one: what is being scanned is somebody's bucket, and uploading its
// contents would put their documents in front of every VirusTotal licensee.
// A file VirusTotal has never seen is reported as unknown, which is the honest
// answer.
type virustotal struct {
	apiKey          string
	mediumThreshold int
	highThreshold   int
}

func (v *virustotal) name() string { return "virustotal" }

func (v *virustotal) request(ctx context.Context, sha256 string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.virustotal.com/api/v3/files/"+sha256, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", v.apiKey)
	return req, nil
}

// parse reports the raw engine counts as well as a derived severity.
//
// Both, because they answer different questions. The counts let a downstream
// consumer apply its own threshold; the severity keeps this scanner comparable
// with the others. One or two detections out of ~70 engines is routinely a false
// positive from a heuristic engine, so a single hit is not treated as decisive.
func (v *virustotal) parse(body []byte) (scanner.Result, error) {
	var data struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				MeaningfulName  string `json:"meaningful_name"`
				TypeDescription string `json:"type_description"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return scanner.Result{}, err
	}

	st := data.Data.Attributes.LastAnalysisStats
	total := st.Malicious + st.Suspicious + st.Harmless + st.Undetected

	res := scanner.Result{
		Match:    st.Malicious > 0,
		Severity: scanner.SeverityInfo,
		Detail: map[string]any{
			"known":      true,
			"malicious":  st.Malicious,
			"suspicious": st.Suspicious,
			"total":      total,
			"file_type":  data.Data.Attributes.TypeDescription,
		},
	}

	switch {
	case st.Malicious >= v.highThreshold:
		res.Severity = scanner.SeverityHigh
	case st.Malicious >= v.mediumThreshold:
		res.Severity = scanner.SeverityMedium
	case st.Malicious > 0:
		res.Severity = scanner.SeverityLow
	}
	return res, nil
}

// NewVirusTotal builds the VirusTotal scanner.
func NewVirusTotal(cfg *config.Config, gdb *gorm.DB) scanner.Scanner {
	return &lookup{
		p: &virustotal{
			apiKey:          cfg.VTAPIKey,
			mediumThreshold: cfg.VTSeverityMedium,
			highThreshold:   cfg.VTSeverityHigh,
		},
		gdb:        gdb,
		client:     &http.Client{Timeout: 20 * time.Second},
		enabled:    cfg.EnableVT && cfg.VTAPIKey != "",
		cacheTTL:   cfg.IntelCacheTTL,
		dailyQuota: cfg.VTDailyQuota,
	}
}
