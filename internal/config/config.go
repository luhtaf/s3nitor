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
	DBDriver     string
	DBDSN        string
	EnableOTX    bool
	EnableIOC    bool
	EnableYara   bool
	IOCPath      string
	YARAPath     string
	YARACmd      string
	OTXAPIKey    string
	S3Bucket     string
	S3Prefix     string
	S3AccessKey  string
	S3SecretKey  string
	S3Endpoint   string
	S3Region     string
	ReporterType string // "json" | "elasticsearch" | "loki" | "prometheus"
	ReporterPath string // kalau json ke file
	ESUrl        string // url elasticsearch
	ESIndex      string // index elasticsearch
	// ESUsername/ESPassword or ESAPIKey. Any Elasticsearch worth sending
	// findings to has security on, and the reporter previously sent no
	// credentials at all — which fails as a 401 that looks like a network fault.
	ESUsername string
	ESPassword string
	ESAPIKey   string
	// ESCACert is a path to the CA that signed the cluster certificate. ECK
	// generates its own CA, so the system trust store does not contain it.
	ESCACert string
	// ESInsecureSkipVerify disables certificate verification. For a self-signed
	// cluster on a trusted network only — it removes the guarantee that the
	// endpoint receiving your findings is the one you meant.
	ESInsecureSkipVerify bool
	LokiURL              string // url loki
	PrometheusURL        string // url prometheus

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

	// SpillScanners names the scanners whose full queue spills to the pending
	// store instead of blocking upstream.
	//
	// The distinction is how long the wait is, not how slow the scanner is. CPU
	// saturation clears in seconds, so blocking is honest backpressure. An API
	// quota clears in hours, so blocking on it hands your throughput to a third
	// party — a four-per-minute VirusTotal key sharing a queue with the local
	// scanners would cap the entire pipeline at four files per minute.
	SpillScanners []string

	// ScannerRatePerMin bounds requests for quota-limited scanners, keyed by
	// scanner name.
	ScannerRatePerMin map[string]float64

	// PendingRetryBase is the first backoff step; each attempt doubles it.
	PendingRetryBase time.Duration
	// Sandbox detonation. Off by default: it sends the object to a third-party
	// analysis service, which for a bucket of customer data is a decision
	// somebody has to make deliberately rather than inherit from a default.
	EnableSandbox bool
	// SandboxKind selects the API dialect: cuckoo or cape. Named rather than
	// sniffed — the two answer similar-looking JSON on different paths, so a
	// wrong guess fails in ways that look like a broken deployment.
	SandboxKind        string
	SandboxURL         string
	SandboxAPIKey      string
	SandboxHTTPTimeout time.Duration
	// SandboxMaxObjectSize skips objects too large to detonate usefully. The
	// skip is published as a document rather than dropped, because a missing
	// document reads downstream as "clean".
	SandboxMaxObjectSize int64
	// Score thresholds on the backend's own 0-10 scale. The raw score travels
	// in the document's detail, so a consumer that disagrees can apply its own
	// without re-running the analysis.
	SandboxSeverityMedium   float64
	SandboxSeverityHigh     float64
	SandboxSeverityCritical float64

	// ScanTimeout bounds one synchronous Scan call.
	//
	// Without it a single object can hold a CPU lane indefinitely: YARA shells
	// out, and a rule with pathological backtracking against a large file runs
	// for as long as it likes. The deadline is per call, not per object — a
	// scanner that hits it and can be resumed hands its token on instead of
	// discarding the work it already paid for.
	ScanTimeout time.Duration

	// AsyncTopic carries resume tokens for scans that outlive the call that
	// started them, kept separate from the bucket-notification topic.
	//
	// Two topics rather than one because the messages differ in kind and in
	// lifetime: an event says "this object appeared" and is consumed in
	// milliseconds, while a continuation says "this analysis is still running
	// elsewhere" and may be re-queued for hours. Sharing a topic would put a
	// sandbox that polls for an hour in front of the next upload.
	AsyncTopic string
	// AsyncGroupID is the async worker's consumer group, separate from the
	// scanner's so the two never steal each other's messages.
	AsyncGroupID string
	// AsyncPollInterval is how long a continuation waits before being polled
	// again after the sandbox says "not yet".
	AsyncPollInterval time.Duration
	// AsyncSweepInterval is how often the worker looks in the ledger for
	// continuations the broker never delivered.
	AsyncSweepInterval time.Duration
	// AsyncMaxAge abandons a continuation whose analysis never finishes, so a
	// sandbox that silently drops a submission does not leave the task pending
	// forever with no document ever published.
	AsyncMaxAge time.Duration

	// PendingMaxAttempts stops a task that keeps failing from being retried
	// forever. Past it the task is marked failed and the failure is published,
	// so it is visible rather than silently absent.
	PendingMaxAttempts int

	// --- where work comes from ---

	// SourceMode is "lister" or "event". One or the other: a hybrid needs a
	// schedule and a way to distinguish a reconciling pass from a live one.
	SourceMode string
	// EventTransport is "redis" or "kafka"; EventFormat names the payload
	// dialect. The two vary independently — MinIO publishes to either broker.
	EventTransport string
	EventFormat    string

	RedisAddr     string
	RedisPassword string
	RedisKey      string
	RedisDB       int

	KafkaBrokers []string
	KafkaTopic   string
	KafkaGroupID string

	// --- threat intel ---

	EnableVT bool
	VTAPIKey string
	// VTSeverityMedium and VTSeverityHigh are engine-count thresholds. One or
	// two detections out of roughly seventy engines is routinely a heuristic
	// false positive, so a single hit does not mean high.
	VTSeverityMedium int
	VTSeverityHigh   int
	// VTDailyQuota stops the scanner before the provider does. Being cut off
	// mid-run by a 429 wastes the lookups already spent; stopping early leaves
	// the remainder parked for the next day.
	VTDailyQuota int

	// IntelCacheTTL bounds how long a third-party verdict is trusted. A file
	// unknown last week may be documented malware today.
	IntelCacheTTL time.Duration

	// MetricsAddr serves /metrics. Empty disables the server.
	MetricsAddr string
}

func Load() *Config {
	_ = godotenv.Load()

	return &Config{
		DBDriver:             os.Getenv("DB_DRIVER"),
		DBDSN:                os.Getenv("DB_DSN"),
		EnableOTX:            os.Getenv("ENABLE_OTX") == "true",
		EnableIOC:            os.Getenv("ENABLE_IOC") == "true",
		EnableYara:           os.Getenv("ENABLE_YARA") == "true",
		IOCPath:              getOrDefault("IOC_PATH", "rules/ioc/"),
		YARAPath:             getOrDefault("YARA_PATH", "rules/yara/"),
		YARACmd:              getOrDefault("YARA_CMD", "yara"),
		OTXAPIKey:            os.Getenv("OTX_API_KEY"),
		S3Bucket:             os.Getenv("S3_BUCKET"),
		S3Prefix:             os.Getenv("S3_PREFIX"),
		S3AccessKey:          os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:          os.Getenv("S3_SECRET_KEY"),
		S3Endpoint:           os.Getenv("S3_ENDPOINT"),
		S3Region:             os.Getenv("S3_REGION"),
		ReporterType:         os.Getenv("REPORTER_TYPE"),
		ReporterPath:         os.Getenv("REPORTER_PATH"),
		ESUrl:                os.Getenv("ES_URL"),
		ESIndex:              os.Getenv("ES_INDEX"),
		ESUsername:           os.Getenv("ES_USERNAME"),
		ESPassword:           os.Getenv("ES_PASSWORD"),
		ESAPIKey:             os.Getenv("ES_API_KEY"),
		ESCACert:             os.Getenv("ES_CA_CERT"),
		ESInsecureSkipVerify: os.Getenv("ES_INSECURE_SKIP_VERIFY") == "true",
		LokiURL:              os.Getenv("LOKI_URL"),
		PrometheusURL:        os.Getenv("PROMETHEUS_URL"),

		FetchByteBudget: getBytes("FETCH_BYTE_BUDGET", 512*MB),
		FetchMaxConns:   getInt("FETCH_MAX_CONNS", 16),
		MaxObjectSize:   getBytes("MAX_OBJECT_SIZE", 1*GB),

		AnalyzeCPULimit: getInt("ANALYZE_CPU_LIMIT", 0),

		PublishBatchSize:     getInt("PUBLISH_BATCH_SIZE", 100),
		PublishFlushInterval: getDuration("PUBLISH_FLUSH_INTERVAL", 2*time.Second),
		PublishMaxBytes:      getBytes("PUBLISH_MAX_BYTES", 5*MB),

		StageQueueSize: getInt("STAGE_QUEUE_SIZE", 1000),

		SpillScanners: getList("SPILL_SCANNERS", []string{"otx", "virustotal", "sandbox"}),
		ScannerRatePerMin: map[string]float64{
			"otx":        float64(getInt("OTX_RATE_PER_MIN", 600)),
			"virustotal": float64(getInt("VT_RATE_PER_MIN", 4)), // free tier
		},
		EnableSandbox:      os.Getenv("ENABLE_SANDBOX") == "true",
		SandboxKind:        getOrDefault("SANDBOX_KIND", "cape"),
		SandboxURL:         os.Getenv("SANDBOX_URL"),
		SandboxAPIKey:      os.Getenv("SANDBOX_API_KEY"),
		SandboxHTTPTimeout: getDuration("SANDBOX_HTTP_TIMEOUT", 2*time.Minute),
		// 100MB: past that the upload itself starts costing more than the
		// analysis is worth, and most sandboxes refuse it anyway.
		SandboxMaxObjectSize:    getBytes("SANDBOX_MAX_OBJECT_SIZE", 100*MB),
		SandboxSeverityMedium:   getFloat("SANDBOX_SEVERITY_MEDIUM", 3),
		SandboxSeverityHigh:     getFloat("SANDBOX_SEVERITY_HIGH", 6),
		SandboxSeverityCritical: getFloat("SANDBOX_SEVERITY_CRITICAL", 8),

		ScanTimeout:        getDuration("SCAN_TIMEOUT", 2*time.Minute),
		AsyncTopic:         getOrDefault("ASYNC_TOPIC", "s3nitor-scan-async"),
		AsyncGroupID:       getOrDefault("ASYNC_GROUP_ID", "s3nitor-async"),
		AsyncPollInterval:  getDuration("ASYNC_POLL_INTERVAL", 30*time.Second),
		AsyncSweepInterval: getDuration("ASYNC_SWEEP_INTERVAL", time.Minute),
		AsyncMaxAge:        getDuration("ASYNC_MAX_AGE", 6*time.Hour),

		PendingRetryBase:   getDuration("PENDING_RETRY_BASE", 30*time.Second),
		PendingMaxAttempts: getInt("PENDING_MAX_ATTEMPTS", 5),

		SourceMode:     getOrDefault("SOURCE_MODE", "lister"),
		EventTransport: getOrDefault("EVENT_TRANSPORT", "redis"),
		EventFormat:    getOrDefault("EVENT_FORMAT", "minio"),
		RedisAddr:      getOrDefault("REDIS_ADDR", "localhost:6379"),
		RedisPassword:  os.Getenv("REDIS_PASSWORD"),
		RedisKey:       getOrDefault("REDIS_KEY", "s3nitor-events"),
		RedisDB:        getInt("REDIS_DB", 0),
		KafkaBrokers:   getList("KAFKA_BROKERS", []string{"localhost:9092"}),
		KafkaTopic:     getOrDefault("KAFKA_TOPIC", "s3nitor-events"),
		KafkaGroupID:   getOrDefault("KAFKA_GROUP_ID", "s3nitor"),

		EnableVT:         os.Getenv("ENABLE_VT") == "true",
		VTAPIKey:         os.Getenv("VT_API_KEY"),
		VTSeverityMedium: getInt("VT_SEVERITY_MEDIUM", 3),
		VTSeverityHigh:   getInt("VT_SEVERITY_HIGH", 10),
		VTDailyQuota:     getInt("VT_DAILY_QUOTA", 500),
		IntelCacheTTL:    getDuration("INTEL_CACHE_TTL", 168*time.Hour),
		MetricsAddr:      getUnlessSet("METRICS_ADDR", ":8080"),
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

// getList reads a comma-separated setting. An explicitly empty value means an
// empty list, not the default — SPILL_SCANNERS="" is how you say "nothing
// spills".
func getList(key string, def []string) []string {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
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

// getFloat reads a fractional setting, keeping the default on a bad value.
//
// Sandbox scores are fractional (Cuckoo and CAPE both report things like 6.4),
// so rounding them to an int would move every threshold by up to a whole point.
func getFloat(key string, def float64) float64 {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		log.Printf("config: %s=%q is not a number, using %g", key, raw, def)
		return def
	}
	return v
}
