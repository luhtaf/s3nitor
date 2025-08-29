# S3-GPT Scanner

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/luhtaf/s3nitor)](https://goreportcard.com/report/github.com/luhtaf/s3nitor)

> **Enterprise-grade S3-compatible storage scanner for malicious content detection**

A high-performance Go application designed for security professionals and DevOps teams to scan S3-compatible storage systems (AWS S3, MinIO, DigitalOcean Spaces, etc.) for malicious content using advanced modular scanners and flexible reporting systems.

## 🚀 Features

### 🔍 Multi-Engine Scanning
- **OTX Scanner**: AlienVault Open Threat Exchange integration for threat intelligence
- **IOC Scanner**: Indicator of Compromise detection (MD5, SHA1, SHA256 hash matching)
- **YARA Scanner**: Advanced pattern-based malware detection with custom rules
- **Hash Scanner**: Efficient file hash computation and comparison

### 📊 Flexible Reporting
- **JSON Reporter**: Local file output with structured data
- **Elasticsearch Reporter**: Real-time indexing for SIEM integration
- **Loki Reporter**: Log aggregation and centralized logging
- **Prometheus Reporter**: Metrics collection and monitoring

### 🏗️ Enterprise Architecture
- **S3-Compatible Storage**: Support for AWS S3, MinIO, DigitalOcean Spaces, Backblaze B2
- **Database Tracking**: SQLite-based file tracking to prevent re-scanning
- **Worker Pool**: Configurable concurrent processing for optimal performance
- **Graceful Shutdown**: Proper cleanup and signal handling
- **Modular Design**: Easy to extend with custom scanners and reporters

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## ⚡ Quick Start

### Prerequisites

- **Go 1.21+** - [Download](https://golang.org/dl/)
- **S3-Compatible Storage Access** - AWS S3, MinIO, DigitalOcean Spaces, etc.
- **YARA** (Optional) - For malware detection
  ```bash
  # Ubuntu/Debian
  sudo apt install yara
  
  # macOS
  brew install yara
  
  # Windows
  # Download from https://github.com/VirusTotal/yara/releases
  ```

### 1. Clone & Setup

```bash
git clone https://github.com/luhtaf/s3nitor
cd s3nitor
go mod download
```

### 2. Configure Environment

```bash
cp env.example .env
# Edit .env with your S3 credentials and settings
```

### 3. Run Scanner

```bash
go run cmd/s3scanner/main.go
```

## 🛠️ Installation

### From Source

```bash
# Clone repository
git clone https://github.com/luhtaf/s3nitor
cd s3nitor

# Install dependencies
go mod download
go mod tidy

# Build binary
go build -o s3scanner cmd/s3scanner/main.go

# Run
./s3scanner
```

### Using Makefile

```bash
# Build application
make build

# Run tests
make test

# Format code
make fmt

# Build Docker image
make docker-build

# Show all commands
make help
```

### Docker Deployment

```bash
# Build image
docker build -t s3scanner .

# Run with environment file
docker run --env-file .env s3scanner

# Run with environment variables
docker run \
  -e S3_BUCKET=my-bucket \
  -e S3_ACCESS_KEY=xxx \
  -e S3_SECRET_KEY=xxx \
  s3scanner
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| **Database** |
| `DB_DRIVER` | Database driver | `sqlite3` | No |
| `DB_DSN` | Database connection string | `./s3scanner.db` | No |
| **Scanners** |
| `ENABLE_OTX` | Enable OTX scanner | `true` | No |
| `ENABLE_IOC` | Enable IOC scanner | `true` | No |
| `ENABLE_YARA` | Enable YARA scanner | `true` | No |
| `YARA_PATH` | YARA rules directory | `rules/yara/` | No |
| `YARA_CMD` | YARA executable path | `yara` | No |
| `IOC_PATH` | IOC rules directory | `rules/ioc/` | No |
| **S3 Configuration** |
| `S3_BUCKET` | Bucket/container name | - | **Yes** |
| `S3_PREFIX` | Object prefix filter | - | No |
| `S3_ACCESS_KEY` | Access key | - | **Yes** |
| `S3_SECRET_KEY` | Secret key | - | **Yes** |
| `S3_ENDPOINT` | Endpoint URL | `https://s3.amazonaws.com` | No |
| **Performance** |
| `WORKER_COUNT` | Worker goroutines | `0` (auto-detect) | No |
| **Reporting** |
| `REPORTER_TYPE` | Output format | `json` | No |
| `REPORTER_PATH` | Output file path | `./scan-results.json` | No |
| `ES_URL` | Elasticsearch URL | - | If using ES |
| `ES_INDEX` | Elasticsearch index | - | If using ES |
| `LOKI_URL` | Loki URL | - | If using Loki |
| `PROMETHEUS_URL` | Prometheus URL | - | If using Prometheus |

### Scanner Configuration

#### IOC Scanner
Place IOC files in `rules/ioc/`:
```
rules/ioc/
├── md5.txt      # MD5 hashes (one per line)
├── sha1.txt     # SHA1 hashes (one per line)
└── sha256.txt   # SHA256 hashes (one per line)
```

#### YARA Scanner
Place YARA rule files (`.yar`) in `rules/yara/`:

```yara
rule suspicious_pe {
    meta:
        description = "Detects suspicious PE files"
        author = "Security Team"
        date = "2024-01-01"
    strings:
        $s1 = "This program cannot be run in DOS mode"
        $s2 = "MZ" at 0
    condition:
        $s1 and $s2
}
```

## 🚀 Usage

### Basic Scanning

```bash
# Scan with default settings
go run cmd/s3scanner/main.go

# Scan specific prefix
export S3_PREFIX=uploads/
go run cmd/s3scanner/main.go
```

### Advanced Configurations

#### JSON Output
```bash
export REPORTER_TYPE=json
export REPORTER_PATH=./results.json
go run cmd/s3scanner/main.go
```

#### Elasticsearch Integration
```bash
export REPORTER_TYPE=elasticsearch
export ES_URL=http://localhost:9200
export ES_INDEX=s3-scan-results
go run cmd/s3scanner/main.go
```

#### Custom Worker Count
```bash
export WORKER_COUNT=8
go run cmd/s3scanner/main.go
```

### S3-Compatible Storage Examples

#### AWS S3
```bash
export S3_ENDPOINT=https://s3.amazonaws.com
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=your-aws-access-key
export S3_SECRET_KEY=your-aws-secret-key
```

#### MinIO
```bash
export S3_ENDPOINT=http://localhost:9000
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=your-minio-access-key
export S3_SECRET_KEY=your-minio-secret-key
```

#### DigitalOcean Spaces
```bash
export S3_ENDPOINT=https://nyc3.digitaloceanspaces.com
export S3_BUCKET=my-space
export S3_ACCESS_KEY=your-do-access-key
export S3_SECRET_KEY=your-do-secret-key
```

#### Backblaze B2
```bash
export S3_ENDPOINT=https://s3.us-west-002.backblazeb2.com
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=your-b2-key-id
export S3_SECRET_KEY=your-b2-application-key
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   S3 Storage    │    │   S3 Fetcher    │    │  Worker Pool    │
│                 │───▶│                 │───▶│                 │
│ • List Objects  │    │ • Download      │    │ • Process Files │
│ • Metadata      │    │ • Local Temp    │    │ • Concurrent    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Reporters     │◀───│  Scanner Engine │◀───│  Scan Context   │
│                 │    │                 │    │                 │
│ • JSON          │    │ • OTX Scanner   │    │ • File Info     │
│ • Elasticsearch │    │ • IOC Scanner   │    │ • Results       │
│ • Loki          │    │ • YARA Scanner  │    │ • Metadata      │
│ • Prometheus    │    │ • Hash Scanner  │    └─────────────────┘
└─────────────────┘    └─────────────────┘
```

### Data Flow

1. **S3 Fetcher**: Lists objects and downloads files to temporary storage
2. **Worker Pool**: Processes files concurrently using configurable workers
3. **Scanner Engine**: Applies multiple scanning engines to each file
4. **Reporter**: Sends results to configured output destinations
5. **Database**: Tracks processed files to avoid re-scanning

## 📁 Project Structure

```
s3nitor/
├── cmd/
│   └── s3scanner/
│       └── main.go                 # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go              # Configuration management
│   ├── db/
│   │   ├── db.go                  # Database operations
│   │   └── file_record.go         # File record model
│   ├── reporter/
│   │   ├── factory.go             # Reporter factory
│   │   ├── reporter.go            # Reporter interface
│   │   ├── json.go                # JSON reporter
│   │   ├── elasticsearch.go       # Elasticsearch reporter
│   │   ├── loki.go                # Loki reporter
│   │   └── prometheus.go          # Prometheus reporter
│   ├── s3fetcher/
│   │   └── s3fetcher.go           # S3 operations
│   └── scanner/
│       ├── scanner.go             # Scanner interface
│       ├── types.go               # Common types
│       ├── otx_scanner.go         # OTX scanner
│       ├── ioc_scanner.go         # IOC scanner
│       ├── yara_scanner.go        # YARA scanner
│       └── hash_scanner.go        # Hash scanner
├── rules/
│   ├── ioc/                       # IOC rule files
│   │   ├── md5.txt
│   │   ├── sha1.txt
│   │   └── sha256.txt
│   └── yara/                      # YARA rule files
│       └── example.yar
├── env.example                    # Environment template
├── Dockerfile                     # Docker configuration
├── Makefile                       # Build automation
└── README.md                      # This file
```

## 🔧 Development

### Adding New Scanners

1. **Create scanner file** in `internal/scanner/` (e.g., `clamav_scanner.go`)
2. **Implement Scanner interface**:
   ```go
   type Scanner interface {
       Name() string
       Enabled() bool
       Scan(ctx context.Context, sc *ScanContext) error
   }
   ```
3. **Add configuration** in `internal/config/config.go`
4. **Register scanner** in the engine factory
5. **Add tests** and **update documentation**

### Adding New Reporters

1. **Create reporter file** in `internal/reporter/` (e.g., `slack_reporter.go`)
2. **Implement Reporter interface**:
   ```go
   type Reporter interface {
       Report(ctx context.Context, sc *scanner.ScanContext) error
   }
   ```
3. **Add configuration** in `internal/config/config.go`
4. **Register reporter** in the factory
5. **Add tests** and **update documentation**

### Development Commands

```bash
# Run tests
go test ./...

# Format code
go fmt ./...

# Run linter
golangci-lint run

# Generate documentation
godoc -http=:6060
```

## 🚨 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **S3 Access Denied** | Check credentials and bucket permissions |
| **Scanner Errors** | Verify rule files exist and are properly formatted |
| **Reporter Failures** | Check network connectivity to reporting systems |
| **Memory Issues** | Reduce worker count or implement file size limits |
| **YARA Not Found** | Install YARA or specify correct path in `YARA_CMD` |

### Logging

The application logs to stdout. For production:

```bash
# Redirect to log file
go run cmd/s3scanner/main.go > s3scanner.log 2>&1

# With timestamp
go run cmd/s3scanner/main.go 2>&1 | tee -a s3scanner-$(date +%Y%m%d).log
```

### Performance Tuning

- **Worker Count**: Set based on CPU cores and network bandwidth
- **S3 Prefix**: Use prefixes to limit scan scope
- **Database**: Consider PostgreSQL/MySQL for production
- **Memory**: Ensure sufficient disk space for temporary files

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Contribution Ideas

**Scanners:**
- ClamAV integration
- VirusTotal API scanner
- Custom regex pattern scanner
- File type detection scanner
- Entropy analysis scanner
- MISP API Scanner
- OpenCTI API Scanner

**Reporters:**
- Slack/Discord webhook reporter
- Email notification reporter
- JIRA ticket creation reporter
- Custom webhook reporter
- Syslog reporter

**Improvements:**
- Performance optimizations
- Better error handling
- Additional configuration options
- Documentation improvements
- Docker improvements

### Contribution Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Add tests** for new functionality
5. **Ensure** all tests pass (`go test ./...`)
6. **Format** your code (`go fmt ./...`)
7. **Submit** a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ by Luhtaf**
