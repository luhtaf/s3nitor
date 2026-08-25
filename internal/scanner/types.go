package scanner

import (
	"context"
	"time"
)

// Severity grades a finding on one scale across every scanner, so a consumer
// can ask "show me everything above medium" without knowing which scanner
// produced what.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ScanInput is everything a scanner is given about one object. It is built once
// in the fetch stage and read by every scanner.
//
// Read-only by contract. The previous design handed scanners a shared struct
// they each mutated, which was safe only because they ran one after another;
// running them concurrently would have turned the shared results map into a
// concurrent map write, which the Go runtime answers with a fatal error rather
// than a recoverable panic.
type ScanInput struct {
	FileID  string
	Bucket  string
	Key     string
	Version string // ETag where the storage has one, mtime where it does not
	Size    int64

	// Hashes is keyed by algorithm ("md5", "sha1", "sha256") and is computed
	// during the download rather than by a scanner, so hash-consuming scanners
	// have no ordering dependency on one another.
	Hashes map[string]string

	// LocalPath is empty when the fetch was skipped, which happens when the
	// hashes are already known and no pending scanner needs the bytes. Scanners
	// that report NeedsPayload() == false must not read it.
	LocalPath string
}

// Result is one scanner's verdict on one object.
type Result struct {
	Match    bool           `json:"match"`
	Severity Severity       `json:"severity"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// Scanner examines one object and returns its own verdict.
//
// Implementations must be safe to call concurrently for different inputs: the
// analyze stage fans out across scanners and across objects at once.
type Scanner interface {
	Name() string
	Enabled() bool

	// NeedsPayload reports whether Scan reads ScanInput.LocalPath. Hash-only
	// scanners return false, which lets a retried task skip re-downloading the
	// object and lets the fetch stage release the temp file sooner.
	NeedsPayload() bool

	// RulesVersion identifies the ruleset this scanner is currently using, so a
	// changed ruleset can invalidate this scanner's prior results without
	// forcing every other scanner to run again.
	RulesVersion() string

	Scan(ctx context.Context, in *ScanInput) (Result, error)
}

// FileResult carries one object's identity together with every scanner's
// verdict on it.
//
// This exists only while the single worker loop is still in place: it collects
// what used to accumulate in the shared ScanContext so the reporters keep
// emitting the same envelope as before. Once the staged pipeline lands, each
// scanner result is published on its own and there is nothing left to collect.
type FileResult struct {
	FileID   string
	Bucket   string
	Key      string
	Version  string
	Size     int64
	Hashes   map[string]string
	Results  map[string]Result
	ScanTime time.Time
}

// Engine holds the registered scanners.
type Engine struct {
	scanners []Scanner
}

// Scanners exposes the registered set, for callers that need to schedule work
// per scanner rather than per file.
func (e *Engine) Scanners() []Scanner { return e.scanners }
