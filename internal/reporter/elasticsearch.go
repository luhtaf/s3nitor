package reporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// ElasticsearchReporter indexes findings, one document each.
type ElasticsearchReporter struct {
	url   string
	index string
	http  *http.Client

	// Exactly one of these is used, API key first. Held rather than baked into
	// a RoundTripper so the value never lands in a logged request dump.
	apiKey   string
	username string
	password string
}

func NewElasticsearchReporter(cfg *config.Config) (*ElasticsearchReporter, error) {
	if cfg.ESUrl == "" || cfg.ESIndex == "" {
		return nil, fmt.Errorf("invalid elasticsearch config: url=%s index=%s", cfg.ESUrl, cfg.ESIndex)
	}
	transport, err := esTransport(cfg)
	if err != nil {
		return nil, err
	}

	r := &ElasticsearchReporter{
		url:      strings.TrimRight(cfg.ESUrl, "/"),
		index:    cfg.ESIndex,
		http:     &http.Client{Timeout: 30 * time.Second, Transport: transport},
		apiKey:   cfg.ESAPIKey,
		username: cfg.ESUsername,
		password: cfg.ESPassword,
	}

	// Best-effort, before the first document: an index born with dynamic
	// mapping cannot be aggregated over, and by the time anyone notices there
	// is data in it that would have to be reindexed.
	if err := r.EnsureTemplate(context.Background()); err != nil {
		log.Printf("elasticsearch: %v (findings will still be written)", err)
	}
	return r, nil
}

// esTransport configures TLS for the cluster certificate.
//
// A managed Elasticsearch — ECK, for instance — signs its HTTP certificate with
// a CA it generated itself, which is not in the system trust store. Without
// either that CA or an explicit opt-out, every request fails certificate
// verification, and the error reads like a network problem rather than a
// configuration one.
func esTransport(cfg *config.Config) (http.RoundTripper, error) {
	if cfg.ESCACert == "" && !cfg.ESInsecureSkipVerify {
		return http.DefaultTransport, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.ESCACert != "" {
		pem, err := os.ReadFile(cfg.ESCACert)
		if err != nil {
			return nil, fmt.Errorf("reading ES_CA_CERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ES_CA_CERT %q contains no usable certificate", cfg.ESCACert)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ESInsecureSkipVerify {
		// Announced, because a silent opt-out of verification is how a
		// misdirected endpoint goes unnoticed.
		log.Printf("elasticsearch: TLS verification disabled by ES_INSECURE_SKIP_VERIFY")
		tlsCfg.InsecureSkipVerify = true
	}

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tlsCfg
	return t, nil
}

// authorize attaches credentials, preferring an API key over a password.
//
// An API key can be scoped to just the index this writes to; the elastic
// superuser cannot be scoped at all.
func (r *ElasticsearchReporter) authorize(req *http.Request) {
	switch {
	case r.apiKey != "":
		req.Header.Set("Authorization", "ApiKey "+r.apiKey)
	case r.username != "":
		req.SetBasicAuth(r.username, r.password)
	}
}

// Report indexes a single finding under its deterministic id, so a replayed
// result overwrites itself instead of duplicating.
func (r *ElasticsearchReporter) Report(ctx context.Context, f *scanner.Finding) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/%s/_doc/%s", r.url, r.index, f.DocID())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.authorize(req)

	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("elasticsearch: %s: %s", resp.Status, snippet(resp))
	}
	return nil
}

// snippet returns a little of the error body.
//
// Elasticsearch explains refusals in the body — a mapping conflict, a missing
// privilege — and reporting only the status code turns a precise message into
// a bare "403 Forbidden".
func snippet(resp *http.Response) string {
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil || len(b) == 0 {
		return "no body"
	}
	return strings.TrimSpace(string(b))
}

// ReportBatch writes the whole batch in one _bulk request.
//
// Elasticsearch charges far more per request than per document, so a hundred
// individual calls cost roughly a hundred times what one bulk call does.
func (r *ElasticsearchReporter) ReportBatch(ctx context.Context, batch []*scanner.Finding) error {
	if len(batch) == 0 {
		return nil
	}

	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, f := range batch {
		meta := map[string]any{
			"index": map[string]any{"_index": r.index, "_id": f.DocID()},
		}
		if err := enc.Encode(meta); err != nil {
			return err
		}
		if err := enc.Encode(f); err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/_bulk", r.url), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	r.authorize(req)

	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("elasticsearch bulk: %s: %s", resp.Status, snippet(resp))
	}

	// A bulk request returns 200 even when individual documents failed, so the
	// per-item statuses have to be read rather than assumed clean.
	var result struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Error json.RawMessage `json:"error"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("elasticsearch bulk: decoding response: %w", err)
	}
	if result.Errors {
		for _, item := range result.Items {
			for _, detail := range item {
				if detail.Error != nil {
					return fmt.Errorf("elasticsearch bulk: %s", detail.Error)
				}
			}
		}
	}
	return nil
}
