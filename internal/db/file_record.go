package db

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// FileRecord is what we know about one *version* of one object.
//
// Keyed by FileID — sha256(bucket ‖ key ‖ version) — rather than by
// (bucket, object_key). That single change removes the dedup disagreement the
// old schema carried: because the version is baked into the key, the presence
// of a row already means "this exact content has been seen", so there is no
// second timestamp comparison that can disagree with the first.
//
// The hashes are cached so a scanner that needs only hashes can be retried
// without downloading the object again.
type FileRecord struct {
	FileID    string `gorm:"primaryKey;size:64"`
	Bucket    string `gorm:"index;not null"`
	ObjectKey string `gorm:"index;not null"`
	Version   string `gorm:"size:128"` // ETag, or mtime where the storage has no ETag
	Size      int64

	MD5    string `gorm:"size:32;index"`
	SHA1   string `gorm:"size:40;index"`
	SHA256 string `gorm:"size:64;index"`

	LastModified time.Time
	FetchedAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Migrate creates or updates the tables.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&FileRecord{}, &ScanTask{}, &IntelCache{})
}

// UpsertFileRecord writes the record, overwriting an existing row for the same
// FileID.
//
// An upsert rather than read-then-write: two stages may record the same object
// concurrently, and the previous read-compare-write left a window between the
// check and the save.
func UpsertFileRecord(db *gorm.DB, rec *FileRecord) error {
	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "file_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"bucket", "object_key", "version", "size",
			"md5", "sha1", "sha256", "last_modified", "fetched_at", "updated_at",
		}),
	}).Create(rec).Error
}

// SeenFileIDs reports which of the given ids already have a record.
//
// Batched on purpose. The old code issued one query per object inside the
// worker loop; a thousand objects meant a thousand round trips. Discovery hands
// over whole pages, so one query answers the lot.
func SeenFileIDs(db *gorm.DB, ids []string) (map[string]bool, error) {
	seen := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return seen, nil
	}

	const chunk = 500 // keep the IN clause under driver parameter limits
	for start := 0; start < len(ids); start += chunk {
		end := min(start+chunk, len(ids))

		var found []string
		if err := db.Model(&FileRecord{}).
			Where("file_id IN ?", ids[start:end]).
			Pluck("file_id", &found).Error; err != nil {
			return nil, err
		}
		for _, id := range found {
			seen[id] = true
		}
	}
	return seen, nil
}
