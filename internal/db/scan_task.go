package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Task status values.
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// ScanTask is one row per (file × scanner).
//
// The unit is deliberately not "file": scanners finish at wildly different
// times — a hash lookup returns in microseconds, a VirusTotal query may wait
// hours behind a quota — so "this file is scanned" is not a state the system
// can hold. One row per pair lets IOC be done while VirusTotal is still
// pending, and lets a changed ruleset invalidate one scanner without
// rescheduling the rest.
//
// The table does triple duty: pending queue, retry ledger, and dedup key. It
// deliberately holds no results — those live in the reporter sink. The database
// only schedules.
type ScanTask struct {
	FileID  string `gorm:"primaryKey;size:64"`
	Scanner string `gorm:"primaryKey;size:32"`

	Status       string `gorm:"size:16;index"`
	RulesVersion string `gorm:"size:32"`

	Attempts      int
	NextAttemptAt time.Time `gorm:"index"`
	LastError     string

	// ResumeToken identifies work still running outside this process — a Cuckoo
	// task id, a CAPE analysis id. Its meaning belongs to the scanner that
	// issued it; nothing here interprets it.
	//
	// Its presence changes what a retry means. Without a token, retrying a task
	// re-runs the scan from the object, which for a sandbox means uploading the
	// bytes again. With one, retrying is a poll: the analysis is already
	// underway and only its verdict is missing. That is why a timeout can be a
	// handoff rather than a loss.
	ResumeToken string `gorm:"size:128"`
	// SubmittedAt is when the external work started, used to abandon an
	// analysis that never finishes. A sandbox that silently drops a submission
	// would otherwise leave this row pending forever and publish no document at
	// all — which reads downstream as "clean", not as "never answered".
	SubmittedAt time.Time

	// A lease rather than a plain running flag: if the process dies, the row
	// would otherwise stay "running" forever. Reclaiming expired leases is safe
	// with several replicas, whereas resetting every running row at startup
	// would steal work from pods that are still healthy.
	LeasedBy       string    `gorm:"size:64;index"`
	LeaseExpiresAt time.Time `gorm:"index"`

	StartedAt  time.Time
	FinishedAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// MarkDone records a finished task.
//
// Callers must only invoke this *after* the result is durable in the sink.
// Reversed, a crash between the two loses the finding permanently: the task
// reads as complete, so it is never scheduled again.
func MarkDone(db *gorm.DB, fileID, scanner string) error {
	return db.Model(&ScanTask{}).
		Where("file_id = ? AND scanner = ?", fileID, scanner).
		Updates(map[string]any{
			"status":           StatusDone,
			"finished_at":      time.Now().UTC(),
			"leased_by":        "",
			"lease_expires_at": time.Time{},
		}).Error
}

// EnqueueContinuation parks a task whose work is already running elsewhere.
//
// Distinct from EnqueuePending, which parks work that has not started: this one
// records the token and the submission time, and schedules the first poll
// rather than a retry. Attempts is deliberately not incremented — polling a
// running analysis is not a failed attempt, and counting it that way would let
// PENDING_MAX_ATTEMPTS abandon a sandbox job purely for being slow.
func EnqueueContinuation(db *gorm.DB, fileID, scannerName, rulesVersion, token string, pollIn time.Duration) error {
	now := time.Now().UTC()
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "file_id"}, {Name: "scanner"}},
		DoUpdates: clause.Assignments(map[string]any{
			"status":          StatusPending,
			"rules_version":   rulesVersion,
			"resume_token":    token,
			"submitted_at":    now,
			"next_attempt_at": now.Add(pollIn),
			"updated_at":      now,
		}),
	}).Create(&ScanTask{
		FileID:        fileID,
		Scanner:       scannerName,
		Status:        StatusPending,
		RulesVersion:  rulesVersion,
		ResumeToken:   token,
		SubmittedAt:   now,
		NextAttemptAt: now.Add(pollIn),
	}).Error
}

// RescheduleContinuation moves the next poll out without touching the token or
// the attempt count.
func RescheduleContinuation(db *gorm.DB, fileID, scannerName string, pollIn time.Duration) error {
	now := time.Now().UTC()
	return db.Model(&ScanTask{}).
		Where("file_id = ? AND scanner = ?", fileID, scannerName).
		Updates(map[string]any{
			"status":          StatusPending,
			"leased_by":       "",
			"next_attempt_at": now.Add(pollIn),
			"updated_at":      now,
		}).Error
}

// EnqueuePending parks a (file, scanner) pair for a later attempt.
//
// Used when a lane's queue is full and the wait is unbounded — an API quota
// clears in hours, and blocking the pipeline on it would let a third party
// dictate throughput. The task is durable, so a restart picks it up rather than
// losing it.
//
// An upsert, because the same pair can spill on consecutive runs and the row
// should carry the accumulated attempt count rather than reset.
func EnqueuePending(db *gorm.DB, fileID, scannerName, rulesVersion string, backoff time.Duration) error {
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "file_id"}, {Name: "scanner"}},
		DoUpdates: clause.Assignments(map[string]any{
			"status":          StatusPending,
			"rules_version":   rulesVersion,
			"next_attempt_at": time.Now().UTC().Add(backoff),
			"updated_at":      time.Now().UTC(),
		}),
	}).Create(&ScanTask{
		FileID:        fileID,
		Scanner:       scannerName,
		Status:        StatusPending,
		RulesVersion:  rulesVersion,
		NextAttemptAt: time.Now().UTC().Add(backoff),
	}).Error
}

// ClaimPending takes up to limit due tasks, marking them running under a lease.
//
// The lease is what makes a crash recoverable without stranding work: a row left
// "running" by a dead process becomes claimable again once the lease expires.
// Resetting every running row at startup would be simpler and wrong — with more
// than one replica it would steal work from pods that are still healthy.
func ClaimPending(db *gorm.DB, instance string, leaseFor time.Duration, limit int) ([]ScanTask, error) {
	now := time.Now().UTC()

	var claimed []ScanTask
	err := db.Transaction(func(tx *gorm.DB) error {
		var candidates []ScanTask
		if err := tx.Where(
			"(status = ? AND next_attempt_at <= ?) OR (status = ? AND lease_expires_at <= ?)",
			StatusPending, now, StatusRunning, now,
		).Limit(limit).Find(&candidates).Error; err != nil {
			return err
		}
		if len(candidates) == 0 {
			return nil
		}

		for i := range candidates {
			t := &candidates[i]
			res := tx.Model(&ScanTask{}).
				Where("file_id = ? AND scanner = ? AND updated_at = ?", t.FileID, t.Scanner, t.UpdatedAt).
				Updates(map[string]any{
					"status":           StatusRunning,
					"leased_by":        instance,
					"lease_expires_at": now.Add(leaseFor),
					"attempts":         t.Attempts + 1,
					"started_at":       now,
					"updated_at":       now,
				})
			if res.Error != nil {
				return res.Error
			}
			// A zero row count means somebody else claimed it between the read
			// and the write; skip rather than run it twice.
			if res.RowsAffected == 1 {
				t.Attempts++
				claimed = append(claimed, *t)
			}
		}
		return nil
	})
	return claimed, err
}

// MarkFailed records a terminal failure, so a task that keeps breaking stops
// being retried forever and becomes visible instead.
func MarkFailed(db *gorm.DB, fileID, scannerName, reason string) error {
	return db.Model(&ScanTask{}).
		Where("file_id = ? AND scanner = ?", fileID, scannerName).
		Updates(map[string]any{
			"status":           StatusFailed,
			"last_error":       reason,
			"finished_at":      time.Now().UTC(),
			"leased_by":        "",
			"lease_expires_at": time.Time{},
			"updated_at":       time.Now().UTC(),
		}).Error
}
