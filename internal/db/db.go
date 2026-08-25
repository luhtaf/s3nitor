package db

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/luhtaf/s3nitor/internal/config"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// NewDB opens the configured database and sets the connection pool.
//
// The pool was previously left at the database/sql defaults, which allow
// unlimited open connections. That was survivable while one worker loop did all
// the work; it stops being survivable once several stages query concurrently.
func NewDB(cfg *config.Config) (*gorm.DB, error) {
	var dialector gorm.Dialector
	dsn := cfg.DBDSN

	switch cfg.DBDriver {
	case "sqlite3":
		dsn = sqliteDSN(dsn)
		dialector = sqlite.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported DB_DRIVER: %s", cfg.DBDriver)
	}

	gdb, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, err
	}

	if cfg.DBDriver == "sqlite3" {
		// SQLite serialises writers. WAL plus a busy timeout lets readers
		// proceed during a write and makes a contended writer wait rather than
		// fail, but a large pool still buys nothing here — the writes queue
		// either way.
		sqlDB.SetMaxOpenConns(4)
		sqlDB.SetMaxIdleConns(4)
	} else {
		sqlDB.SetMaxOpenConns(25)
		sqlDB.SetMaxIdleConns(5)
	}
	sqlDB.SetConnMaxLifetime(time.Hour)

	return gdb, nil
}

// sqliteDSN adds the pragmas that keep concurrent access from failing outright.
//
// Without _journal_mode=WAL and a busy timeout, a second writer gets
// "database is locked" immediately instead of waiting its turn. Any pragma the
// caller set explicitly is left alone.
func sqliteDSN(dsn string) string {
	if dsn == "" {
		dsn = "./s3scanner.db"
	}

	base, query, _ := strings.Cut(dsn, "?")
	params, err := url.ParseQuery(query)
	if err != nil {
		log.Printf("db: cannot parse DSN parameters, using them as given: %v", err)
		return dsn
	}

	for key, value := range map[string]string{
		"_journal_mode": "WAL",
		"_busy_timeout": "5000",
	} {
		if params.Get(key) == "" {
			params.Set(key, value)
		}
	}
	return base + "?" + params.Encode()
}
