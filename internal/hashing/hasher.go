// Package hashing computes the digests every hash-consuming scanner needs.
//
// This used to be a Scanner that opened the downloaded file and read it back,
// which meant every object was read twice: once from the network onto disk, and
// once from disk to hash it. A Hasher is an io.Writer instead, so the fetch
// stage can tee the download through it and pay for a single pass:
//
//	io.Copy(io.MultiWriter(tmpFile, h), resp.Body)
package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
)

// Hasher computes MD5, SHA1 and SHA256 over everything written to it.
//
// Not safe for concurrent use: one Hasher belongs to one object being fetched.
type Hasher struct {
	md5    hash.Hash
	sha1   hash.Hash
	sha256 hash.Hash
	multi  io.Writer
	n      int64
}

// New returns a Hasher ready to accept bytes.
func New() *Hasher {
	h := &Hasher{
		md5:    md5.New(),
		sha1:   sha1.New(),
		sha256: sha256.New(),
	}
	h.multi = io.MultiWriter(h.md5, h.sha1, h.sha256)
	return h
}

// Write feeds bytes to all three digests. It never returns an error: the
// underlying hash writers are documented never to fail.
func (h *Hasher) Write(p []byte) (int, error) {
	n, err := h.multi.Write(p)
	h.n += int64(n)
	return n, err
}

// Sum returns the digests as lowercase hex, keyed by algorithm name. The keys
// match the filenames under rules/ioc/ so a lookup needs no translation.
func (h *Hasher) Sum() map[string]string {
	return map[string]string{
		"md5":    hex.EncodeToString(h.md5.Sum(nil)),
		"sha1":   hex.EncodeToString(h.sha1.Sum(nil)),
		"sha256": hex.EncodeToString(h.sha256.Sum(nil)),
	}
}

// Size reports how many bytes have been written so far. Useful when the object
// size is not known ahead of the transfer.
func (h *Hasher) Size() int64 { return h.n }

// FileID derives a stable identifier for one version of one object.
//
// It must be computable from listing metadata alone, because dedup runs in the
// discover stage before anything is downloaded — which rules out the content
// SHA256 (not known yet) and a database autoincrement (would orphan documents
// already published under the old id if the database were rebuilt).
//
// version is the ETag where the storage provides one and a modification time
// where it does not; SeaweedFS, for instance, has no S3-style ETag. Any token
// that changes when the content changes keeps dedup correct.
//
// The NUL separators stop different field splits from colliding: bucket "a/b"
// with key "c" must not produce the same id as bucket "a" with key "b/c".
func FileID(bucket, key, version string) string {
	h := sha256.New()
	for _, part := range []string{bucket, key, version} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
