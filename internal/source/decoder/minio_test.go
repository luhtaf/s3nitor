package decoder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a payload captured from real infrastructure in phase 0.
//
// The point of testing against these rather than against hand-written JSON: four
// documented assumptions about these payloads turned out to be wrong, and a test
// built from the same assumptions would have agreed with the bug.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "fixtures", name))
	if err != nil {
		t.Skipf("fixture %s unavailable: %v", name, err)
	}
	return b
}

// The Redis target wraps events as [{"Event":[…]}], which is not the S3 shape.
func TestDecodeRedisEnvelope(t *testing.T) {
	raw := fixture(t, "event-minio-redis.raw.json")

	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		refs, err := MinIO{}.Decode([]byte(line))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		for _, r := range refs {
			got = append(got, r.Key)
			if r.Bucket == "" {
				t.Error("decoded a record with no bucket")
			}
			if r.Size <= 0 {
				t.Errorf("%s: size = %d", r.Key, r.Size)
			}
			if r.Version == "" {
				t.Errorf("%s: no version token, so dedup cannot tell versions apart", r.Key)
			}
		}
	}

	assertKeysDecoded(t, got)
}

// The Kafka target uses {"Records":[…]} — same instance, same event, different
// envelope.
func TestDecodeRecordsEnvelope(t *testing.T) {
	raw := fixture(t, "event-minio-kafka.raw.json")

	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		refs, err := MinIO{}.Decode([]byte(line))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		for _, r := range refs {
			got = append(got, r.Key)
		}
	}

	assertKeysDecoded(t, got)
}

// assertKeysDecoded checks the three key shapes phase 0 uploaded, which is where
// the escaping rules show up.
func assertKeysDecoded(t *testing.T, got []string) {
	t.Helper()

	want := map[string]bool{
		"plain.pdf":            false,
		"with space.pdf":       false, // arrives as with+space.pdf
		"nested/deep/path.pdf": false, // arrives as nested%2Fdeep%2Fpath.pdf
	}
	for _, k := range got {
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Errorf("key %q was not decoded; got %v", key, got)
		}
	}
}

// The escaping rule, pinned. PathUnescape leaves '+' alone and returns a key
// that does not exist, without an error — so only QueryUnescape is correct.
func TestKeyEscaping(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"plain.pdf", "plain.pdf"},
		{"with+space.pdf", "with space.pdf"},
		{"nested%2Fdeep%2Fpath.pdf", "nested/deep/path.pdf"},
		{"with%20space.pdf", "with space.pdf"},
	}
	for _, tc := range tests {
		got, err := decodeKey(tc.raw)
		if err != nil {
			t.Errorf("decodeKey(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("decodeKey(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// Streamed uploads report CompleteMultipartUpload. Matching only on :Put drops
// them silently, which is the worst way for a scanner to miss a file.
func TestMultipartUploadsAreNotMissed(t *testing.T) {
	payload := []byte(`{"Records":[{"eventName":"s3:ObjectCreated:CompleteMultipartUpload",
		"s3":{"bucket":{"name":"b"},"object":{"key":"big.bin","size":100,"eTag":"e-1"}}}]}`)

	refs, err := MinIO{}.Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("decoded %d refs, want 1 — a multipart upload was dropped", len(refs))
	}
	if refs[0].Key != "big.bin" {
		t.Errorf("key = %q", refs[0].Key)
	}
}

// Deletions and other event types are not scanning work.
func TestNonCreationEventsAreIgnored(t *testing.T) {
	payload := []byte(`{"Records":[{"eventName":"s3:ObjectRemoved:Delete",
		"s3":{"bucket":{"name":"b"},"object":{"key":"gone.pdf"}}}]}`)

	refs, err := MinIO{}.Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("decoded %d refs from a delete event, want 0", len(refs))
	}
}

func TestMalformedPayloads(t *testing.T) {
	if refs, err := (MinIO{}).Decode([]byte("   ")); err != nil || refs != nil {
		t.Errorf("blank payload: refs=%v err=%v, want no refs and no error", refs, err)
	}
	for _, bad := range []string{"not json", `{"Records":`, `"a string"`} {
		if _, err := (MinIO{}).Decode([]byte(bad)); err == nil {
			t.Errorf("Decode(%q) succeeded, want an error", bad)
		}
	}
}
