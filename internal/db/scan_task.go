package db

import (
	"time"

	"gorm.io/gorm"
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
