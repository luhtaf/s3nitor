// Package async carries scans that outlive the call that started them.
//
// A sandbox detonation runs for minutes to hours in a service that is not this
// one. Holding a lane open for that would let a third party set the pipeline's
// throughput, and holding the payload would let it set the disk usage. So the
// scan is handed off instead: whatever started the work returns a token, and a
// separate worker collects the verdict later.
//
// What travels is a continuation, not a work item. The bytes already went to
// the sandbox at submit time, so resuming needs the token and enough metadata to
// write the document — never the object again. That is why the async worker
// needs no S3 credentials, and why releasing the payload at handoff is safe.
package async

import (
	"context"
	"time"

	"github.com/luhtaf/s3nitor/internal/scanner"
)

// Continuation is one scan still running somewhere else.
//
// It carries the fields the eventual document needs rather than a FileID alone.
// The alternative — look the object back up when the verdict arrives — would
// make the worker depend on the scanner's database and would fail for an object
// deleted in the meantime, losing a verdict that had already been paid for.
type Continuation struct {
	FileID  string            `json:"file_id"`
	Bucket  string            `json:"bucket"`
	Key     string            `json:"key"`
	Version string            `json:"version"`
	Size    int64             `json:"size"`
	Hashes  map[string]string `json:"hashes,omitempty"`

	Scanner      string `json:"scanner"`
	RulesVersion string `json:"rules_version"`

	// Token is opaque here. Only the scanner that issued it knows whether it is
	// a Cuckoo task id or a CAPE analysis id.
	Token string `json:"token"`

	SubmittedAt time.Time `json:"submitted_at"`
	// PollAfter is when this is worth looking at again. Kafka has no delayed
	// delivery, so a message that arrives early is re-queued rather than waited
	// on — blocking the consumer would stall every other continuation behind
	// the slowest analysis.
	PollAfter time.Time `json:"poll_after"`
}

// FromInput builds a continuation from the input a scanner was given and the
// token it returned.
func FromInput(in *scanner.ScanInput, s scanner.Scanner, pe *scanner.PendingError, defaultPoll time.Duration) Continuation {
	wait := pe.RetryAfter
	if wait <= 0 {
		wait = defaultPoll
	}
	now := time.Now().UTC()
	return Continuation{
		FileID:       in.FileID,
		Bucket:       in.Bucket,
		Key:          in.Key,
		Version:      in.Version,
		Size:         in.Size,
		Hashes:       in.Hashes,
		Scanner:      s.Name(),
		RulesVersion: s.RulesVersion(),
		Token:        pe.Token,
		SubmittedAt:  now,
		PollAfter:    now.Add(wait),
	}
}

// Finding turns a collected verdict into the document that gets published.
//
// Deliberately built from the continuation rather than re-derived, so the
// document a resumed scan produces is identical to the one the inline path
// would have produced — same fields, and therefore the same deterministic
// DocID. Replay stays an overwrite whichever path got there.
func (c Continuation) Finding(res scanner.Result, scanErr error) *scanner.Finding {
	in := &scanner.ScanInput{
		FileID:  c.FileID,
		Bucket:  c.Bucket,
		Key:     c.Key,
		Version: c.Version,
		Size:    c.Size,
		Hashes:  c.Hashes,
	}
	return scanner.NewFindingFor(in, c.Scanner, c.RulesVersion, res, scanErr)
}

// Publisher hands a continuation to whatever collects it.
//
// An interface rather than a Kafka client because lister mode must not acquire a
// broker dependency: with no publisher configured the ledger alone carries the
// task, and the worker's sweeper picks it up on its next pass. Kafka only makes
// the handoff prompt — it is not what makes it durable.
type Publisher interface {
	Publish(ctx context.Context, c Continuation) error
	Close() error
}

// Discard is the no-op publisher used when no broker is configured.
type Discard struct{}

func (Discard) Publish(context.Context, Continuation) error { return nil }
func (Discard) Close() error                                { return nil }
