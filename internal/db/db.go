package db

import (
	"fmt"

	"github.com/luhtaf/s3nitor/internal/config"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// NewDB buat koneksi DB sesuai driver
func NewDB(cfg *config.Config) (*gorm.DB, error) {
	var dialector gorm.Dialector

	switch cfg.DBDriver {
	case "sqlite3":
		dialector = sqlite.Open(cfg.DBDSN)
	case "mysql":
		dialector = mysql.Open(cfg.DBDSN)
	case "postgres":
		dialector = postgres.Open(cfg.DBDSN)
	default:
		return nil, fmt.Errorf("unsupported DB_DRIVER: %s", cfg.DBDriver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
