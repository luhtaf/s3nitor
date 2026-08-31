package intel

import (
	"encoding/json"
	"testing"

	"github.com/luhtaf/s3nitor/internal/scanner"
)

// The severity ladder is the part a reader of the findings relies on, so it is
// pinned rather than left to whatever the thresholds happen to be.
func TestVirusTotalSeverityLadder(t *testing.T) {
	vt := &virustotal{mediumThreshold: 3, highThreshold: 10}

	tests := []struct {
		malicious int
		wantMatch bool
		wantSev   scanner.Severity
	}{
		{0, false, scanner.SeverityInfo},
		// One or two hits out of ~70 engines is routinely a heuristic false
		// positive, so it is reported but not escalated.
		{1, true, scanner.SeverityLow},
		{2, true, scanner.SeverityLow},
		{3, true, scanner.SeverityMedium},
		{9, true, scanner.SeverityMedium},
		{10, true, scanner.SeverityHigh},
		{60, true, scanner.SeverityHigh},
	}

	for _, tc := range tests {
		body, _ := json.Marshal(map[string]any{
			"data": map[string]any{"attributes": map[string]any{
				"last_analysis_stats": map[string]any{
					"malicious": tc.malicious, "suspicious": 0,
					"harmless": 70 - tc.malicious, "undetected": 0,
				},
				"type_description": "PDF document",
			}},
		})

		res, err := vt.parse(body)
		if err != nil {
			t.Fatalf("parse(%d malicious): %v", tc.malicious, err)
		}
		if res.Match != tc.wantMatch {
			t.Errorf("%d malicious: Match = %v, want %v", tc.malicious, res.Match, tc.wantMatch)
		}
		if res.Severity != tc.wantSev {
			t.Errorf("%d malicious: Severity = %q, want %q", tc.malicious, res.Severity, tc.wantSev)
		}
		// Raw counts travel alongside the derived severity so a downstream
		// consumer can apply its own threshold.
		if got, _ := res.Detail["malicious"].(int); got != tc.malicious {
			t.Errorf("%d malicious: detail lost the raw count, got %v", tc.malicious, res.Detail["malicious"])
		}
		if got, _ := res.Detail["total"].(int); got != 70 {
			t.Errorf("%d malicious: total = %v, want 70", tc.malicious, res.Detail["total"])
		}
	}
}

func TestOTXPulseCount(t *testing.T) {
	o := &otx{}

	clean, err := o.parse([]byte(`{"pulse_info":{"count":0}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if clean.Match || clean.Severity != scanner.SeverityInfo {
		t.Errorf("no pulses gave Match=%v Severity=%q", clean.Match, clean.Severity)
	}

	hit, err := o.parse([]byte(`{"pulse_info":{"count":4}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !hit.Match {
		t.Error("four pulses did not register as a match")
	}
	// Corroboration, not conviction: a pulse means somebody catalogued the hash.
	if hit.Severity != scanner.SeverityMedium {
		t.Errorf("Severity = %q, want medium", hit.Severity)
	}
	if got, _ := hit.Detail["pulse_count"].(int); got != 4 {
		t.Errorf("pulse_count = %v, want 4", hit.Detail["pulse_count"])
	}
}

// Neither intel scanner reads the file, which is what lets a spilled lookup be
// retried without downloading the object a second time.
func TestIntelScannersNeedNoPayload(t *testing.T) {
	for _, l := range []*lookup{{p: &otx{}}, {p: &virustotal{}}} {
		if l.NeedsPayload() {
			t.Errorf("%s asked for the payload but only needs a hash", l.Name())
		}
	}
}
