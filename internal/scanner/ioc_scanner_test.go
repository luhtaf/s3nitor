package scanner

import (
	"context"
	"testing"
)

// newTestIOC builds a scanner with a known set, bypassing the file loading so
// the test exercises the matching logic rather than the disk.
func newTestIOC(md5s, sha1s, sha256s []string) *IOCScanner {
	i := &IOCScanner{
		md5Set:    map[string]bool{},
		sha1Set:   map[string]bool{},
		sha256Set: map[string]bool{},
		enabled:   true,
	}
	for _, h := range md5s {
		i.md5Set[h] = true
	}
	for _, h := range sha1s {
		i.sha1Set[h] = true
	}
	for _, h := range sha256s {
		i.sha256Set[h] = true
	}
	i.version = i.computeVersion()
	return i
}

// The point of the interface change: a scanner is now a pure function of its
// input, so a table test needs no pipeline, no temp files, and no shared state.
func TestIOCScan(t *testing.T) {
	const (
		badMD5    = "d41d8cd98f00b204e9800998ecf8427e"
		badSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		cleanMD5  = "0123456789abcdef0123456789abcdef"
	)
	s := newTestIOC([]string{badMD5}, nil, []string{badSHA256})

	tests := []struct {
		name      string
		hashes    map[string]string
		wantMatch bool
		wantSev   Severity
		wantOn    []string
	}{
		{
			name:      "no hash matches",
			hashes:    map[string]string{"md5": cleanMD5, "sha256": "beef"},
			wantMatch: false,
			wantSev:   SeverityInfo,
			wantOn:    nil,
		},
		{
			name:      "md5 matches",
			hashes:    map[string]string{"md5": badMD5},
			wantMatch: true,
			wantSev:   SeverityHigh,
			wantOn:    []string{"md5"},
		},
		{
			name:      "both algorithms match",
			hashes:    map[string]string{"md5": badMD5, "sha256": badSHA256},
			wantMatch: true,
			wantSev:   SeverityHigh,
			wantOn:    []string{"md5", "sha256"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.Scan(context.Background(), &ScanInput{Hashes: tc.hashes})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got.Match != tc.wantMatch {
				t.Errorf("Match = %v, want %v", got.Match, tc.wantMatch)
			}
			if got.Severity != tc.wantSev {
				t.Errorf("Severity = %q, want %q", got.Severity, tc.wantSev)
			}
			on, _ := got.Detail["matched_on"].([]string)
			if len(on) != len(tc.wantOn) {
				t.Fatalf("matched_on = %v, want %v", on, tc.wantOn)
			}
			for i := range on {
				if on[i] != tc.wantOn[i] {
					t.Errorf("matched_on[%d] = %q, want %q", i, on[i], tc.wantOn[i])
				}
			}
		})
	}
}

// Missing hashes are a caller error, not a clean "no match": reporting false
// would silently record every object as safe if the fetch stage regressed.
func TestIOCScanWithoutHashes(t *testing.T) {
	s := newTestIOC([]string{"abc"}, nil, nil)
	if _, err := s.Scan(context.Background(), &ScanInput{}); err == nil {
		t.Error("expected an error when ScanInput carries no hashes")
	}
}

// The fingerprint drives per-scanner rescheduling, so it must depend on the set
// contents and not on map iteration order.
func TestIOCRulesVersion(t *testing.T) {
	a := newTestIOC([]string{"aaa", "bbb", "ccc"}, nil, nil)
	b := newTestIOC([]string{"ccc", "aaa", "bbb"}, nil, nil)
	if a.RulesVersion() != b.RulesVersion() {
		t.Errorf("version depends on insertion order: %q vs %q", a.RulesVersion(), b.RulesVersion())
	}

	c := newTestIOC([]string{"aaa", "bbb"}, nil, nil)
	if a.RulesVersion() == c.RulesVersion() {
		t.Error("version did not change when the set changed")
	}
}

// NeedsPayload gates whether a retry has to download the object again.
func TestScannerPayloadRequirements(t *testing.T) {
	if newTestIOC(nil, nil, nil).NeedsPayload() {
		t.Error("IOC reads only hashes, so it must not require the payload")
	}
	if (&OTXScanner{}).NeedsPayload() {
		t.Error("OTX reads only the sha256, so it must not require the payload")
	}
	if !(&YARAScanner{}).NeedsPayload() {
		t.Error("YARA reads the file, so it must require the payload")
	}
}
