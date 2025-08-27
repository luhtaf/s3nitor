package db

import (
	"time"

	"gorm.io/gorm"
)

// FileRecord menyimpan metadata file yang sudah discan
type FileRecord struct {
	ID         uint   `gorm:"primaryKey"`
	Bucket     string `gorm:"index;not null"`
	ObjectKey  string `gorm:"index;not null"`
	ETag       string `gorm:"size:64"` // bisa hash / etag S3
	ScanStatus string `gorm:"size:20"` // pending, scanned, failed
	ScanTime   time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DeletedAt  gorm.DeletedAt `gorm:"index"`
}

// Migrate tabel FileRecord
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&FileRecord{})
}

// UpsertFileRecord insert atau update record
func UpsertFileRecord(db *gorm.DB, record *FileRecord) error {
	var existing FileRecord
	tx := db.Where("bucket = ? AND object_key = ?", record.Bucket, record.ObjectKey).First(&existing)
	if tx.Error != nil {
		if tx.Error == gorm.ErrRecordNotFound {
			// file baru → insert, status kosong
			record.ScanStatus = ""
			return db.Create(record).Error
		}
		return tx.Error
	}

	// kalau ETag & UpdatedAt sama → skip update
	if existing.ETag == record.ETag && existing.UpdatedAt.Equal(record.UpdatedAt) {
		return nil
	}

	// file berubah → update metadata aja
	existing.ETag = record.ETag
	existing.UpdatedAt = record.UpdatedAt
	return db.Save(&existing).Error
}

// GetPendingFiles ambil semua file yang belum di-scan
func GetPendingFiles(db *gorm.DB, limit int) ([]FileRecord, error) {
	var files []FileRecord
	err := db.Where("scan_status = ?", "pending").Limit(limit).Find(&files).Error
	return files, err
}
