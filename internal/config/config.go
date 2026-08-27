package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Byte-size units for the pipeline budgets.
const (
	KB int64 = 1 << 10
	MB int64 = 1 << 20
	GB int64 = 1 << 30
)

type Config struct {
	DBDriver      string
	DBDSN         string
	EnableOTX     bool
	EnableIOC     bool
	EnableYara    bool
	IOCPath       string
	YARAPath      string
	YARACmd       string
	OTXAPIKey     string
	S3Bucket      string
	S3Prefix      string
	S3AccessKey   string
	S3SecretKey   string
	S3Endpoint    string
	WorkerCount   int    `envconfig:"WORKER_COUNT" default:"0"`
	ReporterType  string // "json" | "elasticsearch" | "loki" | "prometheus"
	ReporterPath  string // kalau json ke file
	ESUrl         string // url elasticsearch
	ESIndex       string // index elasticsearch
	LokiURL       string // url loki
	PrometheusURL string // url prometheus

	// --- staged pipeline ---
	//
	// Each stage is bounded by the resource it actually contends for, which is
	// why these are not one number. WorkerCount above is now only a fallback
	// for the analyze stage.

	// FetchByteBudget caps the total bytes in flight across the fetch stage.
	// Bytes rather than a file count: ten thousand 10 KB objects and one 100 MB
	// object have wildly different memory costs, and a file count cannot tell
	// them apart.
	FetchByteBudget int64
	// FetchMaxConns caps concurrent transfers regardless of their size.
	FetchMaxConns int
	// MaxObjectSize skips objects larger than this outright. 0 disables.
	MaxObjectSize int64

	// AnalyzeCPULimit bounds concurrent scanning. 0 means GOMAXPROCS: for
	// CPU-bound work there is no better number, and exceeding it only adds
	// context switching.
	AnalyzeCPULimit int

	// PublishBatchSize, PublishFlushInterval and PublishMaxBytes are the three
	// flush triggers; whichever fires first wins. The interval is measured from
	// the moment the first document enters an empty batch, so no document ever
	// waits longer than one interval.
	PublishBatchSize     int
	PublishFlushInterval time.Duration
	PublishMaxBytes      int64

	// StageQueueSize is the buffer between stages. Bounded on purpose: a full
	// queue is what makes a slow stage push back on a fast one.
	StageQueueSize int

	// MetricsAddr serves /metrics. Empty disables the server.
	MetricsAddr string
}

func Load() *Config {
	_ = godotenv.Load()

	workerCount, _ := strconv.Atoi(getOrDefault("WORKER_COUNT", "0"))

	return &Config{
		DBDriver:      os.Getenv("DB_DRIVER"),
		DBDSN:         os.Getenv("DB_DSN"),
		EnableOTX:     os.Getenv("ENABLE_OTX") == "true",
		EnableIOC:     os.Getenv("ENABLE_IOC") == "true",
		EnableYara:    os.Getenv("ENABLE_YARA") == "true",
		IOCPath:       getOrDefault("IOC_PATH", "rules/ioc/"),
		YARAPath:      getOrDefault("YARA_PATH", "rules/yara/"),
		YARACmd:       getOrDefault("YARA_CMD", "yara"),
		OTXAPIKey:     os.Getenv("OTX_API_KEY"),
		S3Bucket:      os.Getenv("S3_BUCKET"),
		S3Prefix:      os.Getenv("S3_PREFIX"),
		S3AccessKey:   os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:   os.Getenv("S3_SECRET_KEY"),
		S3Endpoint:    os.Getenv("S3_ENDPOINT"),
		WorkerCount:   workerCount,
		ReporterType:  os.Getenv("REPORTER_TYPE"),
		ReporterPath:  os.Getenv("REPORTER_PATH"),
		ESUrl:         os.Getenv("ES_URL"),
		ESIndex:       os.Getenv("ES_INDEX"),
		LokiURL:       os.Getenv("LOKI_URL"),
		PrometheusURL: os.Getenv("PROMETHEUS_URL"),

		FetchByteBudget: getBytes("FETCH_BYTE_BUDGET", 512*MB),
		FetchMaxConns:   getInt("FETCH_MAX_CONNS", 16),
		MaxObjectSize:   getBytes("MAX_OBJECT_SIZE", 1*GB),

		AnalyzeCPULimit: getInt("ANALYZE_CPU_LIMIT", 0),

		PublishBatchSize:     getInt("PUBLISH_BATCH_SIZE", 100),
		PublishFlushInterval: getDuration("PUBLISH_FLUSH_INTERVAL", 2*time.Second),
		PublishMaxBytes:      getBytes("PUBLISH_MAX_BYTES", 5*MB),

		StageQueueSize: getInt("STAGE_QUEUE_SIZE", 1000),
		MetricsAddr:    getUnlessSet("METRICS_ADDR", ":8080"),
	}
}

func getOrDefault(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

// getUnlessSet distinguishes an unset variable from one set to the empty string.
//
// getOrDefault treats both as "use the default", which is right for a path but
// wrong wherever empty is itself a choice: METRICS_ADDR="" means do not listen,
// and falling back to the default would bind a port the operator asked not to
// have.
func getUnlessSet(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return def
}

// getInt reads an integer setting, falling back to def when unset or unparseable.
func getInt(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("config: %s=%q is not a number, using %d", key, raw, def)
		return def
	}
	return v
}

// getDuration reads a Go duration ("2s", "500ms", "1h30m").
func getDuration(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("config: %s=%q is not a duration, using %s", key, raw, def)
		return def
	}
	return d
}

// getBytes reads a byte size, falling back to def when unset or unparseable.
func getBytes(key string, def int64) int64 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := ParseBytes(raw)
	if err != nil {
		log.Printf("config: %s=%q is not a size, using %d bytes (%v)", key, raw, def, err)
		return def
	}
	return v
}

// ParseBytes reads a human byte size: "512MB", "1.5 GiB", "1048576".
//
// Memory budgets are written by operators, and "512MB" is far harder to get
// wrong by an order of magnitude than 536870912. KB/MB/GB are treated as
// powers of two, matching how container memory limits are actually reasoned
// about, and the explicit KiB/MiB/GiB spellings mean the same thing.
func ParseBytes(raw string) (int64, error) {
	s := strings.TrimSpace(strings.ToUpper(raw))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	mult := int64(1)
	for _, unit := range []struct {
		suffix string
		factor int64
	}{
		{"KIB", KB}, {"MIB", MB}, {"GIB", GB},
		{"KB", KB}, {"MB", MB}, {"GB", GB},
		{"K", KB}, {"M", MB}, {"G", GB},
		{"B", 1},
	} {
		if strings.HasSuffix(s, unit.suffix) {
			mult = unit.factor
			s = strings.TrimSpace(strings.TrimSuffix(s, unit.suffix))
			break
		}
	}

	value, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q as a number", raw)
	}
	if value < 0 {
		return 0, fmt.Errorf("size cannot be negative: %q", raw)
	}
	return int64(value * float64(mult)), nil
}
