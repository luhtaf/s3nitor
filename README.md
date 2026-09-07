# S3-GPT Scanner

[![Go Version](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/luhtaf/s3nitor)](https://goreportcard.com/report/github.com/luhtaf/s3nitor)

> **Enterprise-grade S3-compatible storage scanner for malicious content detection**

A high-performance Go application designed for security professionals and DevOps teams to scan S3-compatible storage systems (AWS S3, MinIO, DigitalOcean Spaces, etc.) for malicious content using advanced modular scanners and flexible reporting systems.

## 🚀 Features

### 🔍 Multi-Engine Scanning
- **IOC Scanner**: Indicator of Compromise detection (MD5, SHA1, SHA256 hash matching)
- **YARA Scanner**: Pattern-based detection with your own rules
- **OTX Scanner**: AlienVault Open Threat Exchange lookups
- **VirusTotal Scanner**: Hash lookups only — file contents are never uploaded

MD5, SHA1 and SHA256 are computed during the download rather than by a separate
scanner, so each object is read once and the hash-consuming scanners have no
ordering dependency between them.

### 📊 Flexible Reporting
- **JSON Reporter**: Local file output with structured data
- **Elasticsearch Reporter**: Real-time indexing for SIEM integration
- **Loki Reporter**: Log aggregation and centralized logging

Pipeline metrics are served for scraping on `METRICS_ADDR` (`/metrics`), not
pushed — Prometheus is pull-based.

### 🏗️ Enterprise Architecture
- **S3-Compatible Storage**: Support for AWS S3, MinIO, DigitalOcean Spaces, Backblaze B2
- **Database Tracking**: SQLite, MySQL or PostgreSQL, to avoid re-scanning
- **Staged Pipeline**: Each stage is bounded by the resource it actually contends
  for — bytes in flight for transfers, cores for scanning, request rate for
  quota-limited APIs — rather than by one shared worker count
- **Per-scanner Lanes**: A quota-limited lookup parks its work instead of holding
  up the local scanners
- **Event-driven or scheduled**: Consume bucket notifications, or paginate the
  bucket for backfills
- **Graceful Shutdown**: Partial batches are published rather than discarded

## 🗄️ Storage Support

Fetching works on any S3-compatible storage. What differs is **bucket notification**
support, which determines whether event-driven mode is available.

Only combinations marked **tested** have been verified end-to-end against real
infrastructure by the scripts in `test/integration/`. Everything else is listed
from vendor documentation and should be treated as unverified.

| Storage | Fetch (S3 API) | Notification transport | Status |
|---|---|---|---|
| **MinIO** | ✅ | Redis (list, `format=access`) | **tested** — `test/integration/minio-redis.sh` |
| **MinIO** | ✅ | Kafka | **tested** — `test/integration/minio-kafka.sh` |
| **SeaweedFS** | ✅ (via `weed s3`) | Kafka (protobuf, filer layer) | **tested** — `test/integration/seaweedfs-kafka.sh` |
| MinIO | ✅ | AMQP, NATS, MQTT, webhook | untested |
| SeaweedFS | ✅ | SQS, PubSub, RabbitMQ | untested |
| Ceph RGW | ✅ | Kafka, AMQP, HTTP | untested |
| AWS S3 | ✅ | SQS / SNS / EventBridge (no direct Kafka) | untested |
| Backblaze B2 | ✅ | webhook only | untested |
| DigitalOcean Spaces | ✅ | none | fetch only |
| Wasabi | ✅ | none | fetch only |

Tested combinations were verified against real infrastructure: MinIO
`RELEASE.2025-04-08T15-41-24Z`, SeaweedFS 3.80, Kafka 3.9 (KRaft), Redis 7.
Each run uploads a small PDF under three key shapes — plain, containing a space,
and nested under a prefix — then reads every object back and compares bytes.

### Notes from testing MinIO

Verified against MinIO `RELEASE.2025-04-08T15-41-24Z`; captured payload lives in
`test/fixtures/event-minio-redis.json`.

- **Object keys arrive percent-encoded.** Spaces become `+` and `/` becomes `%2F`
  (`nested/deep/path.pdf` → `nested%2Fdeep%2Fpath.pdf`). Decode with Go's
  `url.QueryUnescape` — `url.PathUnescape` leaves `+` untouched and silently
  yields the wrong key.
- **Streamed uploads report `s3:ObjectCreated:CompleteMultipartUpload`**, not
  `:Put`. Subscribe to `s3:ObjectCreated:*` or such uploads are missed.
- **The Redis target wraps events as `[{"Event":[…],"EventTime":…}]`**, not the
  plain `{"Records":[…]}` shape used by webhook targets.
- **ETag is not a content hash** for multipart uploads — it carries a `-N` suffix.
  It is still a valid change-detection token.
- **Redis lists provide no acknowledgement.** `LPOP`/`BRPOP` remove the event
  immediately, so a consumer that dies mid-scan loses it permanently. Fine for
  development; use Kafka where delivery must survive a crash.
- **Configure notification targets with `MINIO_NOTIFY_*` environment variables.**
  `mc admin config set` only stages values until a server restart, and
  `mc admin service restart` requires a TTY so it fails silently under
  `kubectl exec`. Note that env-configured targets appear in **uppercase** in the
  ARN (`arn:minio:sqs::PRIMARY:redis`); read the ARN from `mc admin info --json`
  rather than constructing it.

### The envelope differs per transport, not just per vendor

The same MinIO instance wraps the identical event differently depending on where
it is delivered:

| Transport | Envelope |
|---|---|
| Redis | `[{"Event":[…],"EventTime":…}]` |
| Kafka | `{"EventName":…,"Key":…,"Records":[…]}` |

The Kafka envelope also carries the key **twice, with different encodings**:
top-level `"Key":"bucket/with space.pdf"` is raw and includes the bucket, while
`Records[].s3.object.key` is `with+space.pdf`. Prefer the record field — the
bucket is available separately as `Records[].s3.bucket.name`.

Kafka consumer groups do provide acknowledgement: a consumer killed before
committing receives the message again, which is exactly what Redis lists cannot
offer.

### Notes from testing SeaweedFS

SeaweedFS emits notifications from its **filer** layer rather than its S3 layer,
as **protobuf** (`filer_pb.EventNotification`) rather than JSON. Consequences:

- **Paths, not bucket/key.** Events carry `/buckets/<bucket>/<prefix>` in the
  `directory` field; bucket and key must be derived by stripping the prefix.
- **Keys are not encoded** — spaces appear literally. The opposite of MinIO, so
  unescaping must be per-decoder rather than applied uniformly.
- **A content hash is available.** Chunks carry a base64 MD5 which was verified
  to match the uploaded file exactly. There is still no S3-style ETag.
- **Event amplification is roughly 5:1.** Three uploads produced fifteen filer
  events, six of which pointed at `/buckets/<bucket>/.uploads/…` — unfinished
  multipart fragments rather than real objects. A consumer that does not filter
  `.uploads` will scan partial files and publish bogus results.

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

- **Go 1.25+** - [Download](https://golang.org/dl/) (the floor comes from `pgx v5.10`)
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
| `FETCH_BYTE_BUDGET` | Total bytes the pipeline may hold | `512MB` | No |
| `FETCH_MAX_CONNS` | Concurrent transfers | `16` | No |
| `ANALYZE_CPU_LIMIT` | Concurrent scanning; 0 = GOMAXPROCS | `0` | No |
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

#### Tuning concurrency

Each stage is bounded by the resource it actually contends for, so there is no
single worker count. Bound transfers by bytes rather than file count — ten
thousand small objects and one large one have very different memory costs:

```bash
export FETCH_BYTE_BUDGET=256MB   # total bytes held, network buffers plus temp files
export FETCH_MAX_CONNS=8         # concurrent transfers
export ANALYZE_CPU_LIMIT=0       # 0 means GOMAXPROCS
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

Four stages connected by bounded channels. A stage boundary exists to separate
different resource profiles: discovery waits on pagination, fetch on the network
while holding bytes, local scanners on CPU, and threat-intel lookups on somebody
else's quota. One shared worker count cannot be right for all four, so there
isn't one.

```
  discover  ──►  fetch + hash  ──►  dispatch  ──┬──►  ioc         ──┐  block
  lister or      one pass over      one task    ├──►  yara        ──┤  block
  events         the bytes         per scanner  ├──►  otx         ──┼─►  publish
                                                └──►  virustotal  ──┘  spill
  1 goroutine    byte budget        file × scanner   per-lane limiter   batch + flush
  dedup batched  + conn slots                                          1 goroutine
```

| Stage | Bounded by | Why that unit |
|---|---|---|
| discover | nothing — 1 goroutine | pagination is sequential |
| fetch + hash | **bytes in flight** | ten thousand small objects and one large one cost very different memory; a file count cannot tell them apart |
| analyze | CPU cores, shared | past `GOMAXPROCS`, more goroutines add context switching and no throughput |
| publish | batch size, bytes, interval | the sink charges per request far more than per document |

The byte budget is the global brake. It is held from the start of a transfer
until the payload is deleted after scanning — the bytes are resident that whole
time, first in network buffers and then on disk — so when everything downstream
stalls, fetch runs out of budget and stops pulling.

### Block versus spill

When a lane's queue fills, what happens depends on **how long the wait is**. CPU
saturation clears in seconds, so those lanes push back on the stage upstream. An
API quota clears in hours, so those lanes park the task in the database and move
on: a four-per-minute VirusTotal key sharing a queue with the local scanners
would otherwise cap the entire pipeline at four files per minute.

### Data flow

1. **Discover** lists the bucket, or consumes bucket notifications, and answers
   dedup in one batched query rather than one per object
2. **Fetch** streams each object to disk while hashing it in the same pass
3. **Dispatch** fans one object out to one task per enabled scanner; the payload
   is reference-counted by the scanners that actually read it
4. **Lanes** run each scanner under its own limiter and publish each verdict on
   its own — a slow lookup never delays a fast rule match
5. **Publish** batches findings, and records an object as scanned only *after*
   the sink has accepted them

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
