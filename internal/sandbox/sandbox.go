// Package sandbox submits objects for detonation and collects the verdicts.
//
// The first scanner in this project that does not answer from the call that
// started it. A detonation runs for minutes to hours inside another service, so
// Scan submits and hands back a token; the verdict is collected later by the
// async worker calling Poll.
//
// Cuckoo and CAPE are close cousins — submit a file, get a task id, poll until
// the analysis is reported — but their endpoints, auth headers and response
// shapes all differ. They are two implementations of one interface rather than
// one client with branches, for the same reason the event decoders are: a
// branch per provider inside one function is where a wrong assumption about one
// of them hides.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// backend is what differs between Cuckoo and CAPE.
type backend interface {
	// name is the scanner name that appears on the document.
	name() string
	// submit uploads the object and returns the backend's own task id.
	submit(ctx context.Context, c *http.Client, base string, key string, body io.Reader) (string, error)
	// status reports whether the analysis has finished.
	status(ctx context.Context, c *http.Client, base, token string) (state string, done bool, err error)
	// report returns the backend's own score and whatever detail is worth
	// keeping. Mapping the score onto the shared severity scale is not the
	// backend's business — the thresholds are configurable and belong in one
	// place, not duplicated per provider.
	report(ctx context.Context, c *http.Client, base, token string) (score float64, detail map[string]any, err error)
	// auth stamps whatever credential this backend expects.
	auth(r *http.Request)
}

// Sandbox is the scanner half: submit, then hand off.
type Sandbox struct {
	b       backend
	base    string
	client  *http.Client
	enabled bool

	maxSize    int64
	pollAfter  time.Duration
	sevMedium  float64
	sevHigh    float64
	sevCritica float64
}

// New builds the configured sandbox scanner, or a disabled one.
//
// Disabled rather than absent when unconfigured, matching every other scanner
// here: a misconfigured deployment degrades to fewer scanners rather than
// failing to start.
func New(cfg *config.Config) *Sandbox {
	s := &Sandbox{
		base:       cfg.SandboxURL,
		enabled:    cfg.EnableSandbox,
		maxSize:    cfg.SandboxMaxObjectSize,
		pollAfter:  cfg.AsyncPollInterval,
		sevMedium:  cfg.SandboxSeverityMedium,
		sevHigh:    cfg.SandboxSeverityHigh,
		sevCritica: cfg.SandboxSeverityCritical,
		client:     &http.Client{Timeout: cfg.SandboxHTTPTimeout},
	}

	switch cfg.SandboxKind {
	case "cuckoo":
		s.b = &cuckoo{token: cfg.SandboxAPIKey}
	case "cape":
		s.b = &cape{token: cfg.SandboxAPIKey}
	default:
		if s.enabled {
			log.Printf("Sandbox: SANDBOX_KIND=%q is not supported; use cuckoo or cape", cfg.SandboxKind)
		}
		s.enabled = false
		s.b = &cuckoo{}
	}

	if s.enabled && s.base == "" {
		log.Println("Sandbox: SANDBOX_URL is empty, disabling")
		s.enabled = false
	}
	if !s.enabled {
		log.Println("Sandbox: disabled")
	}
	return s
}

func (s *Sandbox) Name() string       { return s.b.name() }
func (s *Sandbox) Enabled() bool      { return s.enabled }
func (s *Sandbox) NeedsPayload() bool { return true }
func (s *Sandbox) Mode() scanner.Mode { return scanner.ModeAsync }

// RulesVersion is the backend identity rather than a ruleset hash.
//
// There is no local ruleset to hash: the signatures live inside the sandbox and
// change without telling us. Naming the backend at least keeps a Cuckoo verdict
// and a CAPE verdict on the same object as separate documents instead of one
// silently overwriting the other.
func (s *Sandbox) RulesVersion() string { return s.b.name() }

// Timeout bounds the submission, not the analysis.
//
// The analysis is the thing that takes an hour, and it is deliberately not
// waited on. What this bounds is the upload — the only part that happens
// in-line, holding a lane and the payload.
func (s *Sandbox) Timeout() time.Duration { return 0 }

// Scan submits the object and returns a resume token.
//
// It never returns a verdict. The PendingError is the normal outcome here, not
// an error path: the analysis has started, the object has already been handed
// over, and everything left to do is a poll.
func (s *Sandbox) Scan(ctx context.Context, in *scanner.ScanInput) (scanner.Result, error) {
	if in.LocalPath == "" {
		return scanner.Result{}, fmt.Errorf("sandbox: no payload for %s", in.Key)
	}
	if s.maxSize > 0 && in.Size > s.maxSize {
		// Reported rather than skipped silently. An object too big to detonate
		// is exactly the kind of thing worth knowing was not examined, and a
		// missing document reads downstream as "clean".
		return scanner.Result{
			Match:    false,
			Severity: scanner.SeverityInfo,
			Detail: map[string]any{
				"submitted": false,
				"reason":    "exceeds_sandbox_max_object_size",
				"size":      in.Size,
				"max_size":  s.maxSize,
				"analysed":  false,
				"backend":   s.b.name(),
			},
		}, nil
	}

	f, err := os.Open(in.LocalPath)
	if err != nil {
		return scanner.Result{}, fmt.Errorf("sandbox: opening payload: %w", err)
	}
	defer f.Close()

	token, err := s.b.submit(ctx, s.client, s.base, filepath.Base(in.Key), f)
	if err != nil {
		return scanner.Result{}, fmt.Errorf("sandbox: submit %s: %w", in.Key, err)
	}
	return scanner.Result{}, &scanner.PendingError{Token: token, RetryAfter: s.pollAfter}
}

// Poll asks whether the analysis has finished.
//
// Takes only the token: the bytes went to the sandbox at submit time, so
// resuming needs nothing from the object. That is what lets the async worker run
// without S3 credentials.
func (s *Sandbox) Poll(ctx context.Context, token string) (scanner.Result, bool, error) {
	state, done, err := s.b.status(ctx, s.client, s.base, token)
	if err != nil {
		return scanner.Result{}, false, err
	}
	if !done {
		return scanner.Result{}, false, nil
	}
	score, detail, err := s.b.report(ctx, s.client, s.base, token)
	if err != nil {
		return scanner.Result{}, false, err
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["backend"] = s.b.name()
	detail["task_id"] = token
	detail["state"] = state
	detail["analysed"] = true
	return s.Verdict(score, detail), true, nil
}

// severity maps a backend score onto the shared scale.
//
// The raw score travels in Detail alongside it, so a consumer that disagrees
// with these thresholds can apply its own without re-running anything.
func (s *Sandbox) severity(score float64) scanner.Severity {
	switch {
	case score >= s.sevCritica:
		return scanner.SeverityCritical
	case score >= s.sevHigh:
		return scanner.SeverityHigh
	case score >= s.sevMedium:
		return scanner.SeverityMedium
	case score > 0:
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}

// Verdict builds the shared result shape from a backend score.
func (s *Sandbox) Verdict(score float64, detail map[string]any) scanner.Result {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["score"] = score
	return scanner.Result{
		Match:    score >= s.sevMedium,
		Severity: s.severity(score),
		Detail:   detail,
	}
}

// multipartFile builds the upload body both backends use.
func multipartFile(field, filename string, body io.Reader) (io.Reader, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(part, body); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return &buf, w.FormDataContentType(), nil
}

// decodeJSON reads a response, surfacing a snippet of the body on a non-200.
//
// The snippet matters: a sandbox behind an authenticating proxy answers with
// HTML, and "invalid character '<'" sends you looking at the parser instead of
// at the credentials.
func decodeJSON(resp *http.Response, v any) error {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d: %s", resp.StatusCode, snippet(body))
	}
	return json.Unmarshal(body, v)
}

func snippet(b []byte) string {
	const max = 200
	s := string(bytes.TrimSpace(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
