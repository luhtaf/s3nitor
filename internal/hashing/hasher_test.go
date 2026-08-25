package hashing

import (
	"io"
	"strings"
	"testing"
)

// Digests for the empty input and for "abc", from the algorithm specifications.
// Hard-coded on purpose: computing them with the same library under test would
// only prove the library agrees with itself.
const (
	emptyMD5    = "d41d8cd98f00b204e9800998ecf8427e"
	emptySHA1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	abcMD5    = "900150983cd24fb0d6963f7d28e17f72"
	abcSHA1   = "a9993e364706816aba3e25717850c26c9cd0d89d"
	abcSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

func TestSum(t *testing.T) {
	tests := []struct {
		name                     string
		input                    string
		md5sum, sha1sum, sha2sum string
	}{
		{"empty", "", emptyMD5, emptySHA1, emptySHA256},
		{"abc", "abc", abcMD5, abcSHA1, abcSHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := New()
			if _, err := io.Copy(h, strings.NewReader(tc.input)); err != nil {
				t.Fatalf("copy: %v", err)
			}
			got := h.Sum()
			for algo, want := range map[string]string{
				"md5": tc.md5sum, "sha1": tc.sha1sum, "sha256": tc.sha2sum,
			} {
				if got[algo] != want {
					t.Errorf("%s = %q, want %q", algo, got[algo], want)
				}
			}
			if h.Size() != int64(len(tc.input)) {
				t.Errorf("Size() = %d, want %d", h.Size(), len(tc.input))
			}
		})
	}
}

// The fetch stage tees the download through the Hasher rather than reading the
// file back, so the digests must be identical whether the bytes arrive in one
// write or dribble in across many.
func TestChunkedWritesMatchSingleWrite(t *testing.T) {
	const payload = "the quick brown fox jumps over the lazy dog"

	whole := New()
	whole.Write([]byte(payload))

	chunked := New()
	for _, b := range []byte(payload) {
		chunked.Write([]byte{b})
	}

	for algo, want := range whole.Sum() {
		if got := chunked.Sum()[algo]; got != want {
			t.Errorf("%s: chunked = %q, whole = %q", algo, got, want)
		}
	}
}

// Sum must not finalise the digests, so callers may inspect them and keep going.
func TestSumDoesNotConsumeState(t *testing.T) {
	h := New()
	h.Write([]byte("abc"))
	first := h.Sum()
	second := h.Sum()
	if first["sha256"] != second["sha256"] {
		t.Errorf("Sum() is not repeatable: %q then %q", first["sha256"], second["sha256"])
	}
	if first["sha256"] != abcSHA256 {
		t.Errorf("sha256 = %q, want %q", first["sha256"], abcSHA256)
	}
}

func TestFileID(t *testing.T) {
	const (
		bucket  = "uploads"
		key     = "invoice.pdf"
		version = "etag-1"
	)
	base := FileID(bucket, key, version)

	if len(base) != 64 {
		t.Fatalf("FileID length = %d, want 64 hex chars", len(base))
	}
	if again := FileID(bucket, key, version); again != base {
		t.Errorf("FileID is not deterministic: %q then %q", base, again)
	}

	// A new version of the same object must produce a new id, otherwise an
	// overwritten object would be skipped as already scanned.
	if FileID(bucket, key, "etag-2") == base {
		t.Error("changing version did not change the id")
	}

	// The NUL separator has to keep ambiguous field splits apart.
	if FileID("a/b", "c", version) == FileID("a", "b/c", version) {
		t.Error(`bucket "a/b"+key "c" collides with bucket "a"+key "b/c"`)
	}
}
