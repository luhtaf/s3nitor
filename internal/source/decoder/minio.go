// Package decoder turns bucket-notification payloads into object references.
//
// Every field mapping and every quirk here was measured against real MinIO and
// SeaweedFS rather than read from documentation, because four assumptions taken
// from the docs turned out to be wrong. The captured payloads live in
// test/fixtures and are what these decoders are tested against.
package decoder

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/luhtaf/s3nitor/internal/source"
)

// s3Record is the record shape both MinIO envelopes carry inside.
type s3Record struct {
	EventName   string `json:"eventName"`
	EventSource string `json:"eventSource"`
	EventTime   string `json:"eventTime"`
	S3          struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key       string `json:"key"`
			Size      int64  `json:"size"`
			ETag      string `json:"eTag"`
			Sequencer string `json:"sequencer"`
		} `json:"object"`
	} `json:"s3"`
}

// MinIO decodes MinIO bucket notifications.
type MinIO struct{}

func (MinIO) Name() string { return "minio" }

// Decode handles both envelopes MinIO produces.
//
// The envelope depends on the transport, not the vendor: Kafka receives
// {"EventName":…,"Key":…,"Records":[…]} while the Redis target wraps the same
// event as [{"Event":[…],"EventTime":…}]. Recognising only one silently drops
// every message from the other.
func (m MinIO) Decode(payload []byte) ([]source.ObjectRef, error) {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" {
		return nil, nil
	}

	var records []s3Record

	switch trimmed[0] {
	case '[':
		// Redis target: an array of {"Event":[…]} wrappers.
		var wrappers []struct {
			Event []s3Record `json:"Event"`
		}
		if err := json.Unmarshal(payload, &wrappers); err != nil {
			return nil, fmt.Errorf("minio: decoding Redis envelope: %w", err)
		}
		for _, w := range wrappers {
			records = append(records, w.Event...)
		}
	case '{':
		// Kafka and webhook targets: {"Records":[…]}.
		var wrapper struct {
			Records []s3Record `json:"Records"`
		}
		if err := json.Unmarshal(payload, &wrapper); err != nil {
			return nil, fmt.Errorf("minio: decoding Records envelope: %w", err)
		}
		records = wrapper.Records
	default:
		return nil, fmt.Errorf("minio: payload is neither an object nor an array")
	}

	refs := make([]source.ObjectRef, 0, len(records))
	for _, r := range records {
		// Only creations are of interest. Note that a streamed upload arrives as
		// s3:ObjectCreated:CompleteMultipartUpload, not :Put — matching on :Put
		// alone silently misses them.
		if !strings.HasPrefix(r.EventName, "s3:ObjectCreated:") {
			continue
		}

		key, err := decodeKey(r.S3.Object.Key)
		if err != nil {
			return nil, fmt.Errorf("minio: decoding key %q: %w", r.S3.Object.Key, err)
		}

		ref := source.ObjectRef{
			Bucket:  r.S3.Bucket.Name,
			Key:     key,
			Version: r.S3.Object.ETag,
			Size:    r.S3.Object.Size,
		}
		if ref.Version == "" {
			// No ETag in the payload: the sequencer still changes per write, so
			// it keeps dedup honest.
			ref.Version = r.S3.Object.Sequencer
		}
		if t, err := time.Parse(time.RFC3339, r.EventTime); err == nil {
			ref.LastModified = t
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// decodeKey unescapes an object key from a notification.
//
// QueryUnescape, not PathUnescape. Measured: MinIO encodes a space as '+' and a
// slash as %2F, and PathUnescape leaves the plus untouched — returning a key
// that does not exist, with no error. The failure only appears once a file has a
// space in its name, which is why it survives review.
func decodeKey(raw string) (string, error) {
	return url.QueryUnescape(raw)
}
