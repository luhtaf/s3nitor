package scanner

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
)

// HashScanner menghitung hash MD5, SHA1, SHA256
type HashScanner struct {
	enabled bool
}

// NewHashScanner constructor, default selalu enabled
func NewHashScanner() *HashScanner {
	return &HashScanner{enabled: true}
}

func (h *HashScanner) Name() string  { return "hash_scanner" }
func (h *HashScanner) Enabled() bool { return h.enabled }

// Scan menghitung hash file dan menyimpan di ScanContext
func (h *HashScanner) Scan(ctx context.Context, sc *ScanContext) (map[string]interface{}, error) {
	file, err := os.Open(sc.FilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	if _, err := io.Copy(io.MultiWriter(md5h, sha1h, sha256h), file); err != nil {
		return nil, err
	}

	// Encode ke hex string
	md5Str := hex.EncodeToString(md5h.Sum(nil))
	sha1Str := hex.EncodeToString(sha1h.Sum(nil))
	sha256Str := hex.EncodeToString(sha256h.Sum(nil))

	// Simpan di ScanContext.Hashes
	if sc.Hashes == nil {
		sc.Hashes = make(map[string]string)
	}
	sc.Hashes["md5"] = md5Str
	sc.Hashes["sha1"] = sha1Str
	sc.Hashes["sha256"] = sha256Str

	// Simpan juga di Results
	sc.Results[h.Name()] = map[string]string{
		"md5":    md5Str,
		"sha1":   sha1Str,
		"sha256": sha256Str,
	}

	log.Printf("[%s] scanned file %s: md5=%s sha1=%s sha256=%s",
		h.Name(), sc.FilePath, md5Str, sha1Str, sha256Str)

	return sc.Hashes, nil
}
