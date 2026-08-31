package db

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IntelCache stores third-party verdicts keyed by content hash.
//
// Keyed by the hash rather than by FileID on purpose. A threat-intel lookup is a
// pure function of the content: the same payload under twenty different keys, or
// in twenty different buckets, has one answer. With a VirusTotal free-tier key
// allowing four lookups a minute, asking twice for the same bytes is the
// difference between usable and not.
//
// Findings are still published once per object — you need to know which objects
// are affected — but only one API call is spent.
type IntelCache struct {
	Provider string `gorm:"primaryKey;size:32"`
	SHA256   string `gorm:"primaryKey;size:64"`

	// Known is false when the provider returned 404. That is an answer, not a
	// failure, and caching it is what stops an unknown file from being looked up
	// again on every run.
	Known    bool
	Match    bool
	Severity string `gorm:"size:16"`
	Detail   string // JSON, kept as text to avoid a datatypes dependency

	FetchedAt time.Time
	ExpiresAt time.Time `gorm:"index"`
}

// GetIntel returns a cached verdict, or false if absent or expired.
//
// Expiry matters: a verdict is a snapshot of what the provider knew, and a file
// unknown last week may be well-documented malware today.
func GetIntel(db *gorm.DB, provider, sha256 string) (*IntelCache, bool) {
	var row IntelCache
	err := db.Where("provider = ? AND sha256 = ?", provider, sha256).First(&row).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, false
		}
		return nil, false
	}
	if time.Now().UTC().After(row.ExpiresAt) {
		return nil, false
	}
	return &row, true
}

// PutIntel stores a verdict with its expiry.
func PutIntel(db *gorm.DB, row *IntelCache) error {
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "provider"}, {Name: "sha256"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"known", "match", "severity", "detail", "fetched_at", "expires_at",
		}),
	}).Create(row).Error
}
