// Package intel holds the scanners that ask a third party about a hash.
//
// A sibling of scanner rather than a subpackage: these need the cache, the cache
// lives in db, and db already imports nothing from scanner. Nesting them under
// scanner would make scanner import intel to build them, and intel import
// scanner for the interface — a cycle.
//
// OTX and VirusTotal are the same shape: send a SHA256, get back somebody else's
// opinion. What differs is the URL, the auth header and how the response is
// read, so everything else lives here once.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/luhtaf/s3nitor/internal/db"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// provider is what a specific service has to supply.
type provider interface {
	// name is the scanner name and the cache key prefix.
	name() string
	// request builds the lookup for one hash.
	request(ctx context.Context, sha256 string) (*http.Request, error)
	// parse turns a 200 response body into a verdict.
	parse(body []byte) (scanner.Result, error)
}

// lookup is the shared scanner around a provider.
type lookup struct {
	// Sync despite being slow. Slow is not the same as asynchronous: an intel
	// lookup blocks on somebody else's HTTP endpoint and answers from that same
	// call, so it waits rather than handing out a token. What protects the
	// pipeline from its latency is the lane's spill policy, not its mode.
	scanner.SyncScanner

	p        provider
	gdb      *gorm.DB
	client   *http.Client
	enabled  bool
	cacheTTL time.Duration

	// dailyQuota, when set, stops the scanner before the provider does. Being
	// cut off mid-run by a 429 wastes the requests already spent on partial
	// work; stopping early leaves the rest parked for tomorrow.
	dailyQuota int
	spent      int
}

func (l *lookup) Name() string         { return l.p.name() }
func (l *lookup) Enabled() bool        { return l.enabled }
func (l *lookup) NeedsPayload() bool   { return false } // a hash is enough
func (l *lookup) RulesVersion() string { return l.p.name() + "-v1" }

// Scan answers from cache when it can and asks the provider when it cannot.
func (l *lookup) Scan(ctx context.Context, in *scanner.ScanInput) (scanner.Result, error) {
	sha := in.Hashes["sha256"]
	if sha == "" {
		return scanner.Result{}, fmt.Errorf("%s: no sha256 in ScanInput", l.p.name())
	}

	if row, ok := db.GetIntel(l.gdb, l.p.name(), sha); ok {
		return fromCache(row), nil
	}

	if l.dailyQuota > 0 && l.spent >= l.dailyQuota {
		return scanner.Result{}, fmt.Errorf("%s: daily quota of %d exhausted", l.p.name(), l.dailyQuota)
	}

	req, err := l.p.request(ctx, sha)
	if err != nil {
		return scanner.Result{}, err
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return scanner.Result{}, fmt.Errorf("%s: %w", l.p.name(), err)
	}
	defer resp.Body.Close()
	l.spent++

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// The provider has never seen this hash. That is an answer, and caching
		// it is what stops an unknown file being looked up again every run —
		// which on a four-per-minute quota would consume the whole budget on
		// files nobody knows anything about.
		res := scanner.Result{
			Severity: scanner.SeverityInfo,
			Detail:   map[string]any{"known": false},
		}
		l.store(sha, res, false)
		return res, nil

	case resp.StatusCode == http.StatusTooManyRequests:
		// Not cached: a rate limit says nothing about the file.
		return scanner.Result{}, fmt.Errorf("%s: rate limited", l.p.name())

	case resp.StatusCode != http.StatusOK:
		return scanner.Result{}, fmt.Errorf("%s: status %d", l.p.name(), resp.StatusCode)
	}

	body, err := readAll(resp)
	if err != nil {
		return scanner.Result{}, err
	}

	res, err := l.p.parse(body)
	if err != nil {
		return scanner.Result{}, err
	}
	l.store(sha, res, true)
	return res, nil
}

func (l *lookup) store(sha string, res scanner.Result, known bool) {
	detail, err := json.Marshal(res.Detail)
	if err != nil {
		detail = []byte("{}")
	}
	now := time.Now().UTC()
	if err := db.PutIntel(l.gdb, &db.IntelCache{
		Provider:  l.p.name(),
		SHA256:    sha,
		Known:     known,
		Match:     res.Match,
		Severity:  string(res.Severity),
		Detail:    string(detail),
		FetchedAt: now,
		ExpiresAt: now.Add(l.cacheTTL),
	}); err != nil {
		log.Printf("%s: caching verdict: %v", l.p.name(), err)
	}
}

func fromCache(row *db.IntelCache) scanner.Result {
	res := scanner.Result{
		Match:    row.Match,
		Severity: scanner.Severity(row.Severity),
		Detail:   map[string]any{},
	}
	if err := json.Unmarshal([]byte(row.Detail), &res.Detail); err != nil {
		res.Detail = map[string]any{}
	}
	res.Detail["cached"] = true
	return res
}

// readAll drains a response body under a size cap.
//
// Capped because the body is somebody else's output: an unbounded read hands a
// third party control over how much memory this process uses.
func readAll(resp *http.Response) ([]byte, error) {
	const maxBody = 4 << 20
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}
