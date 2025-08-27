package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	DBDriver      string
	DBDSN         string
	EnableOTX     bool
	EnableIOC     bool
	EnableYara    bool
	IOCPath       string
	YARAPath      string
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
	}
}

func getOrDefault(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}
