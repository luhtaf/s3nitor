package sandbox

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/luhtaf/s3nitor/internal/config"
	"github.com/luhtaf/s3nitor/internal/scanner"
)

// testConfig is the smallest config that enables a sandbox.
func testConfig(kind, url string) *config.Config {
	return &config.Config{
		EnableSandbox:           true,
		SandboxKind:             kind,
		SandboxURL:              url,
		SandboxAPIKey:           "secret",
		SandboxMaxObjectSize:    1 << 20,
		SandboxSeverityMedium:   3,
		SandboxSeverityHigh:     6,
		SandboxSeverityCritical: 8,
	}
}

func payload(t *testing.T) *scanner.ScanInput {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("MZ fake sample"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	return &scanner.ScanInput{
		FileID: "f1", Bucket: "b", Key: "dir/sample.bin",
		Size: 14, LocalPath: path,
	}
}

// Submitting must not return a verdict. The whole design rests on the handoff:
// if a submission came back as a Result, the pipeline would publish "clean" for
// an analysis that had not started yet.
func TestSubmitReturnsTokenNotVerdict(t *testing.T) {
	for _, tc := range []struct {
		kind, submitPath, body, wantToken string
	}{
		{"cuckoo", "/tasks/create/file", `{"task_id":417}`, "417"},
		{"cape", "/apiv2/tasks/create/file/", `{"error":false,"data":{"task_ids":[908]}}`, "908"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			var gotPath, gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
				if err := r.ParseMultipartForm(1 << 20); err != nil {
					t.Errorf("body is not multipart: %v", err)
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			s := New(testConfig(tc.kind, srv.URL))
			if !s.Enabled() {
				t.Fatal("scanner disabled")
			}
			if s.Mode() != scanner.ModeAsync {
				t.Errorf("Mode = %v, want async", s.Mode())
			}

			_, err := s.Scan(context.Background(), payload(t))
			pe, ok := scanner.AsPending(err)
			if !ok {
				t.Fatalf("Scan returned %v, want a *PendingError", err)
			}
			if pe.Token != tc.wantToken {
				t.Errorf("token = %q, want %q", pe.Token, tc.wantToken)
			}
			if gotPath != tc.submitPath {
				t.Errorf("submitted to %q, want %q", gotPath, tc.submitPath)
			}
			// The two use different auth schemes, and sending the wrong one is
			// rejected as anonymous rather than as malformed — which looks like
			// a URL problem, not a credential one.
			wantAuth := map[string]string{"cuckoo": "Bearer secret", "cape": "Token secret"}[tc.kind]
			if gotAuth != wantAuth {
				t.Errorf("auth header = %q, want %q", gotAuth, wantAuth)
			}
		})
	}
}

// Polling must distinguish "still running" from "finished", because treating
// the first as the second publishes a verdict from an empty report.
func TestPollWaitsForTerminalState(t *testing.T) {
	for _, tc := range []struct {
		kind, pending, reported string
		reportBody              string
	}{
		{"cuckoo", `{"task":{"status":"running"}}`, `{"task":{"status":"reported"}}`,
			`{"info":{"score":7.5,"category":"file"},"signatures":[{"name":"injection"}]}`},
		{"cape", `{"error":false,"data":"running"}`, `{"error":false,"data":"reported"}`,
			`{"malscore":7.5,"signatures":[{"name":"injection"}],"detections":[{"family":"emotet"}]}`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			finished := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case containsAny(r.URL.Path, "report"):
					w.Write([]byte(tc.reportBody))
				case finished:
					w.Write([]byte(tc.reported))
				default:
					finished = true
					w.Write([]byte(tc.pending))
				}
			}))
			defer srv.Close()

			s := New(testConfig(tc.kind, srv.URL))

			if _, done, err := s.Poll(context.Background(), "1"); err != nil || done {
				t.Fatalf("first poll: done=%v err=%v, want done=false", done, err)
			}

			res, done, err := s.Poll(context.Background(), "1")
			if err != nil || !done {
				t.Fatalf("second poll: done=%v err=%v, want done=true", done, err)
			}
			if !res.Match {
				t.Error("score 7.5 above the medium threshold should match")
			}
			if res.Severity != scanner.SeverityHigh {
				t.Errorf("severity = %q, want high (7.5 is >= 6 and < 8)", res.Severity)
			}
			// The raw score has to survive into the document: a consumer that
			// disagrees with these thresholds must be able to apply its own
			// without re-running the analysis.
			if got := res.Detail["score"]; got != 7.5 {
				t.Errorf("detail score = %v, want 7.5", got)
			}
		})
	}
}

// A failed analysis is terminal. Retrying one forever leaves the task pending
// with no document ever published, and a missing document reads downstream as
// "clean" rather than "never answered".
func TestFailedAnalysisIsTerminalNotRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if containsAny(r.URL.Path, "report") {
			w.Write([]byte(`{"error":false,"malscore":0}`))
			return
		}
		w.Write([]byte(`{"error":false,"data":"failed_analysis"}`))
	}))
	defer srv.Close()

	_, done, err := New(testConfig("cape", srv.URL)).Poll(context.Background(), "1")
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if !done {
		t.Error("failed_analysis must be terminal, or the task polls forever")
	}
}

// CAPE reports errors with HTTP 200 and an in-band flag, so a status check that
// only looks at the code treats a failure as a verdict.
func TestCapeInBandErrorIsNotSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"error":true,"error_value":"Task not found"}`))
	}))
	defer srv.Close()

	if _, _, err := New(testConfig("cape", srv.URL)).Poll(context.Background(), "9999"); err == nil {
		t.Fatal("an HTTP 200 carrying error:true must not be treated as success")
	}
}

// An object too large to detonate is reported, not dropped. Publishing nothing
// would be indistinguishable from a clean verdict.
func TestOversizeObjectIsReportedNotSilentlySkipped(t *testing.T) {
	cfg := testConfig("cape", "http://127.0.0.1:1")
	cfg.SandboxMaxObjectSize = 10

	in := payload(t)
	in.Size = 1 << 20

	res, err := New(cfg).Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Detail["analysed"] != false {
		t.Error("the document must say the object was not analysed")
	}
	if res.Detail["reason"] != "exceeds_sandbox_max_object_size" {
		t.Errorf("reason = %v, want exceeds_sandbox_max_object_size", res.Detail["reason"])
	}
}

// An unreachable sandbox is an error, never a verdict.
func TestSubmitFailureIsNotAVerdict(t *testing.T) {
	_, err := New(testConfig("cape", "http://127.0.0.1:1")).Scan(context.Background(), payload(t))
	if err == nil {
		t.Fatal("a failed submission must not look like a completed scan")
	}
	var pe *scanner.PendingError
	if errors.As(err, &pe) {
		t.Fatal("a failed submission must not produce a resume token")
	}
}

func containsAny(s string, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
