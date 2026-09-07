package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Mode says how a scanner finishes.
//
// This is a different axis from the lane's full-queue policy, which answers
// "what do we do when this scanner's queue is full". Mode answers "does the
// verdict arrive from the call we just made". A scanner can be slow and still
// sync (it blocks, we wait); a scanner can be fast and still async (it hands
// the work to something else that answers later).
type Mode int

const (
	// ModeSync returns the verdict from Scan, within Timeout.
	ModeSync Mode = iota
	// ModeAsync starts work elsewhere and returns a resume token immediately.
	// Nothing waits: the verdict is collected later by the async worker.
	ModeAsync
)

func (m Mode) String() string {
	if m == ModeAsync {
		return "async"
	}
	return "sync"
}

// PendingError reports that a scanner started work it did not finish, and
// carries the token needed to pick it up again.
//
// This is what makes a timeout non-destructive. A sandbox submission has
// already cost the upload of the object; abandoning it on a deadline would
// throw that away and re-submit the same bytes on retry. Returning the token
// instead turns the timeout into a handoff — the external job keeps running,
// and the async worker resumes it by polling that id.
//
// Both modes use it: an async scanner returns it immediately, a sync scanner
// returns it only when its deadline passes with no verdict.
type PendingError struct {
	// Token identifies the work to the scanner that started it. Its meaning is
	// private to that scanner — a Cuckoo task id, a CAPE analysis id — and the
	// pipeline only stores and returns it.
	Token string
	// RetryAfter hints how long to wait before polling. Zero uses the default
	// backoff.
	RetryAfter time.Duration
}

func (e *PendingError) Error() string {
	return "scan pending, resume token " + e.Token
}

// Resumable is implemented by scanners whose work can outlive the call that
// started it. Poll is what the async worker calls with a token from
// PendingError; done reports whether the verdict is final.
//
// Note what Poll does not take: a ScanInput. Resuming needs the token, not the
// bytes — the object was already handed to the sandbox at submit time. That is
// why the async worker needs no S3 credentials and no re-download, and why
// releasing the payload at handoff is safe.
type Resumable interface {
	Poll(ctx context.Context, token string) (result Result, done bool, err error)
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

	// Mode reports whether Scan returns the verdict or a resume token.
	Mode() Mode

	// Timeout bounds one Scan call. Zero means unbounded, which is only
	// reasonable for scanners whose work is local and finite.
	//
	// A bound matters even for local scanners: YARA shells out, and a rule with
	// pathological backtracking against a large file can run far longer than
	// the object is worth. Without a deadline that one object holds a CPU lane
	// for as long as it likes.
	Timeout() time.Duration

	// Scan examines the object.
	//
	// Returning a *PendingError is not a failure: it means the work was started
	// and its verdict will be collected later.
	Scan(ctx context.Context, in *ScanInput) (Result, error)
}

// SyncScanner supplies the Mode and Timeout defaults, so an existing scanner
// becomes conformant by embedding it rather than by growing two methods that
// say nothing.
type SyncScanner struct {
	// ScanTimeout is exported so a constructor can set it from config.
	ScanTimeout time.Duration
}

func (SyncScanner) Mode() Mode               { return ModeSync }
func (s SyncScanner) Timeout() time.Duration { return s.ScanTimeout }

// Finding is one scanner's verdict on one object — the unit that gets published.
//
// This replaces the per-file envelope that FileResult used to carry. Scanners
// finish at wildly different times: an IOC lookup returns in microseconds while
// a VirusTotal query may wait hours behind a quota, so "the result for this
// file" is not a thing that exists at any single moment. Publishing each verdict
// on its own means a slow scanner never holds back a fast one, and the sink —
// which is a document store — reassembles them at query time on FileID.
type Finding struct {
	FileID  string            `json:"file_id"`
	Bucket  string            `json:"bucket"`
	Key     string            `json:"key"`
	Version string            `json:"version"`
	Size    int64             `json:"size"`
	Hashes  map[string]string `json:"hashes,omitempty"`

	Scanner string `json:"scanner"`
	// RulesVersion identifies the ruleset behind this verdict, so a later
	// ruleset change produces a new document rather than overwriting the old
	// one, and history is preserved.
	RulesVersion string `json:"rules_version,omitempty"`

	Match    bool           `json:"match"`
	Severity Severity       `json:"severity"`
	Detail   map[string]any `json:"detail,omitempty"`

	ScannedAt time.Time `json:"scanned_at"`
	// Error is set when the scanner failed rather than returned a verdict. A
	// failure that vanishes silently is indistinguishable from a clean result,
	// which for a security scanner is the worse of the two.
	Error string `json:"error,omitempty"`
}

// NewFinding builds a published verdict from an input and a scanner's result.
func NewFinding(in *ScanInput, s Scanner, res Result, scanErr error) *Finding {
	return NewFindingFor(in, s.Name(), s.RulesVersion(), res, scanErr)
}

// NewFindingFor builds the same document from a scanner's name and ruleset
// rather than the scanner itself.
//
// The async worker needs this: it publishes verdicts for scans it did not run,
// and may not even have the scanner registered. Routing both paths through one
// constructor is what keeps the resumed document byte-identical to the inline
// one, and therefore keeps DocID stable across them.
func NewFindingFor(in *ScanInput, name, rulesVersion string, res Result, scanErr error) *Finding {
	f := &Finding{
		FileID:       in.FileID,
		Bucket:       in.Bucket,
		Key:          in.Key,
		Version:      in.Version,
		Size:         in.Size,
		Hashes:       in.Hashes,
		Scanner:      name,
		RulesVersion: rulesVersion,
		Match:        res.Match,
		Severity:     res.Severity,
		Detail:       res.Detail,
		ScannedAt:    time.Now().UTC(),
	}
	if scanErr != nil {
		f.Error = scanErr.Error()
		f.Severity = SeverityInfo
	}
	if f.Severity == "" {
		f.Severity = SeverityInfo
	}
	return f
}

// DocID is a deterministic identifier for this finding.
//
// At-least-once delivery means the same verdict is occasionally published twice
// — after a crash between publishing and recording, for instance. A derived id
// turns that replay into an overwrite instead of a duplicate, which is what
// makes crash recovery correct rather than merely tidy.
//
// RulesVersion is part of it on purpose: rescanning after a ruleset change is a
// new fact, not a correction of the old one, so it gets its own document.
func (f *Finding) DocID() string {
	sum := sha256.Sum256([]byte(f.FileID + "\x00" + f.Scanner + "\x00" + f.RulesVersion))
	return hex.EncodeToString(sum[:])
}

// Engine holds the registered scanners.
type Engine struct {
	scanners []Scanner
}

// Scanners exposes the registered set, for callers that need to schedule work
// per scanner rather than per file.
func (e *Engine) Scanners() []Scanner { return e.scanners }
