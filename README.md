# S3 Compatible Scanner

A high-performance Go application for scanning S3-compatible storage (AWS S3, MinIO, DigitalOcean Spaces, etc.) for malicious content using modular scanners and flexible reporting systems.

## Features

- **S3 Compatible Storage**: Scan files directly from S3-compatible storage (AWS S3, MinIO, DigitalOcean Spaces, etc.) with efficient downloading
- **Modular Scanners**: Support for multiple scanning engines:
  - **OTX Scanner**: AlienVault Open Threat Exchange integration
  - **IOC Scanner**: Indicator of Compromise detection (MD5, SHA1, SHA256)
  - **YARA Scanner**: Pattern-based malware detection
- **Flexible Reporting**: Multiple output formats:
  - **JSON**: Local file output
  - **Elasticsearch**: Real-time indexing
  - **Loki**: Log aggregation
  - **Prometheus**: Metrics collection
- **Database Tracking**: SQLite-based file tracking to avoid re-scanning unchanged files
- **Worker Pool**: Configurable concurrent processing
- **Graceful Shutdown**: Proper cleanup and signal handling

## Architecture

```
S3-Compatible Storage → S3 Fetcher → Worker Pool → Scanner Engine → Reporter
        ↓                      ↓              ↓            ↓            ↓
    List Objects          Download    Process File   Send Results
        ↓                      ↓              ↓            ↓            ↓
    Metadata              Local Temp   Scan Results   Various Outputs
```

## Prerequisites

- Go 1.21 or higher
- Access to S3-compatible storage (AWS S3, MinIO, DigitalOcean Spaces, etc.)
- YARA executable installed in system PATH (optional, for malware detection)
  - Download from: https://github.com/VirusTotal/yara/releases
  - Or install via package manager: `apt install yara`, `brew install yara`, etc.
- Optional: Elasticsearch, Loki, or Prometheus for reporting

## Dependencies

The project uses the following main dependencies:

- **AWS SDK v2**: For S3 operations (`github.com/aws/aws-sdk-go-v2`)
- **GORM**: Database ORM with support for SQLite, MySQL, and PostgreSQL
- **YARA**: Malware pattern matching (requires YARA executable in system PATH)
- **Godotenv**: Environment variable loading (`github.com/joho/godotenv`)

All dependencies are automatically managed by Go modules.

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd s3-gpt
```

2. Install dependencies:
```bash
go mod download
```

3. Initialize the module (if not already done):
```bash
go mod tidy
```

3. Copy environment template:
```bash
cp .env.example .env
```

4. Configure your environment variables in `.env`

5. Copy the environment template:
```bash
cp env.example .env
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DB_DRIVER` | Database driver | `sqlite3` | No |
| `DB_DSN` | Database connection string | `./s3scanner.db` | No |
| `ENABLE_OTX` | Enable OTX scanner | `true` | No |
| `ENABLE_IOC` | Enable IOC scanner | `true` | No |
| `ENABLE_YARA` | Enable YARA scanner | `true` | No |
| `YARA_PATH` | Path to YARA rules directory | `rules/yara/` | No |
| `YARA_CMD` | YARA executable command/path | `yara` | No |
| `IOC_PATH` | Path to IOC rules | `rules/ioc/` | No |
| `S3_BUCKET` | S3-compatible bucket/container name | - | **Yes** |
| `S3_PREFIX` | S3 object prefix filter | - | No |
| `S3_ACCESS_KEY` | S3-compatible access key | - | **Yes** |
| `S3_SECRET_KEY` | S3-compatible secret key | - | **Yes** |
| `S3_ENDPOINT` | S3-compatible endpoint URL | `https://s3.amazonaws.com` | No |
| `WORKER_COUNT` | Number of worker goroutines | `0` (auto-detect) | No |
| `REPORTER_TYPE` | Output format | `json` | No |
| `REPORTER_PATH` | Output file path (for JSON) | `./scan-results.json` | No |
| `ES_URL` | Elasticsearch URL | - | If using ES |
| `ES_INDEX` | Elasticsearch index | - | If using ES |
| `LOKI_URL` | Loki URL | - | If using Loki |
| `PROMETHEUS_URL` | Prometheus URL | - | If using Prometheus |

### Scanner Configuration

#### IOC Scanner
Place your IOC files in the `rules/ioc/` directory:
- `md5.txt` - MD5 hashes (one per line)
- `sha1.txt` - SHA1 hashes (one per line)
- `sha256.txt` - SHA256 hashes (one per line)

#### YARA Scanner
Place your YARA rule files (`.yar`) in the `rules/yara/` directory. The scanner will automatically detect and use all `.yar` files found in this directory.

**YARA Installation Options:**

1. **System Installation** (Recommended):
   ```bash
   # Ubuntu/Debian
   sudo apt install yara
   
   # macOS
   brew install yara
   
   # Windows
   # Download from https://github.com/VirusTotal/yara/releases
   ```
   Then use default `YARA_CMD=yara` in your `.env` file.

2. **Portable YARA**:
   If you have a portable YARA executable, specify the full path:
   ```bash
   # Example for portable YARA
   YARA_CMD=/path/to/portable/yara.exe
   YARA_CMD=./tools/yara-linux
   YARA_CMD=C:\tools\yara.exe
   ```

Example YARA rule:
```yara
rule suspicious_pe {
    meta:
        description = "Detects suspicious PE files"
    strings:
        $s1 = "This program cannot be run in DOS mode"
    condition:
        $s1
}
```

## Usage

### Basic Usage

```bash
go run cmd/s3scanner/main.go
```

### Build and Run

```bash
# Build the binary
go build -o s3scanner cmd/s3scanner/main.go

# Run the scanner
./s3scanner
```

### Docker

```bash
# Build Docker image
docker build -t s3scanner .

# Run with environment file
docker run --env-file .env s3scanner

# Or run with environment variables
docker run -e S3_BUCKET=my-bucket -e S3_ACCESS_KEY=xxx -e S3_SECRET_KEY=xxx s3scanner
```

### Using Makefile

```bash
# Build the application
make build

# Run tests
make test

# Format code
make fmt

# Build Docker image
make docker-build

# Show all available commands
make help
```

## Examples

### Scan with JSON Output
```bash
export REPORTER_TYPE=json
export REPORTER_PATH=./results.json
go run cmd/s3scanner/main.go
```

### Scan with Elasticsearch Output
```bash
export REPORTER_TYPE=elasticsearch
export ES_URL=http://localhost:9200
export ES_INDEX=s3-scan-results
go run cmd/s3scanner/main.go
```

### Scan Specific Prefix
```bash
export S3_PREFIX=uploads/
go run cmd/s3scanner/main.go
```

### Using Different S3-Compatible Storage

**AWS S3:**
```bash
export S3_ENDPOINT=https://s3.amazonaws.com
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=your-aws-access-key
export S3_SECRET_KEY=your-aws-secret-key
```

**MinIO:**
```bash
export S3_ENDPOINT=http://localhost:9000
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=your-minio-access-key
export S3_SECRET_KEY=your-minio-secret-key
```

**DigitalOcean Spaces:**
```bash
export S3_ENDPOINT=https://nyc3.digitaloceanspaces.com
export S3_BUCKET=my-space
export S3_ACCESS_KEY=your-do-access-key
export S3_SECRET_KEY=your-do-secret-key
```

**Backblaze B2:**
```bash
export S3_ENDPOINT=https://s3.us-west-002.backblazeb2.com
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=your-b2-key-id
export S3_SECRET_KEY=your-b2-application-key
```

### Custom Worker Count
```bash
export WORKER_COUNT=8
go run cmd/s3scanner/main.go
```

### Using Portable YARA
```bash
# If you have YARA in a custom location
export YARA_CMD=/opt/yara/bin/yara
export YARA_PATH=/opt/yara/rules/
go run cmd/s3scanner/main.go

# Or for Windows with portable YARA
export YARA_CMD=C:\tools\yara.exe
export YARA_PATH=C:\tools\rules\
go run cmd/s3scanner/main.go
```

## Project Structure

```
s3-gpt/
├── cmd/
│   └── s3scanner/
│       └── main.go          # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go        # Configuration management
│   ├── db/
│   │   ├── db.go           # Database operations
│   │   └── file_record.go  # File record model
│   ├── reporter/
│   │   ├── factory.go      # Reporter factory
│   │   ├── reporter.go     # Reporter interface
│   │   ├── json.go         # JSON reporter
│   │   ├── elasticsearch.go # Elasticsearch reporter
│   │   ├── loki.go         # Loki reporter
│   │   └── prometheus.go   # Prometheus reporter
│   ├── s3fetcher/
│   │   └── s3fetcher.go    # S3 operations
│   └── scanner/
│       ├── scanner.go      # Scanner interface
│       ├── types.go        # Common types
│       ├── otx_scanner.go  # OTX scanner
│       ├── ioc_scanner.go  # IOC scanner
│       ├── yara_scanner.go # YARA scanner
│       └── hash_scanner.go # Hash scanner
├── rules/
│   └── ioc/                # IOC rule files
│       ├── md5.txt
│       ├── sha1.txt
│       └── sha256.txt
│   └── yara/                # IOC rule files
│       └── rules.yar
├── .env.example            # Environment template
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## Development

### Adding a New Scanner

1. Implement the `Scanner` interface in `internal/scanner/scanner.go`
2. Add configuration options in `internal/config/config.go`
3. Register the scanner in the engine factory

### Adding a New Reporter

1. Implement the `Reporter` interface in `internal/reporter/reporter.go`
2. Add configuration options in `internal/config/config.go`
3. Register the reporter in the factory

### Running Tests

```bash
go test ./...
```

### Code Formatting

```bash
go fmt ./...
```

## Performance Considerations

- **Worker Count**: Set `WORKER_COUNT` based on your CPU cores and network bandwidth
- **S3 Prefix**: Use prefixes to limit scan scope across S3-compatible storage
- **Database**: Consider using a more robust database for production (PostgreSQL, MySQL)
- **Memory**: Large files are downloaded temporarily - ensure sufficient disk space

## Security Considerations

- Store S3-compatible credentials securely (use IAM roles when possible for AWS S3)
- Regularly update IOC and YARA rules
- Monitor scan results for false positives
- Implement proper access controls for reporting systems

## Troubleshooting

### Common Issues

1. **S3 Access Denied**: Check S3-compatible credentials and bucket permissions
2. **Scanner Errors**: Verify rule files exist and are properly formatted
3. **Reporter Failures**: Check network connectivity to reporting systems
4. **Memory Issues**: Reduce worker count or implement file size limits

### Logs

The application logs to stdout. For production, consider redirecting to a log file:

```bash
go run cmd/s3scanner/main.go > s3scanner.log 2>&1
```

## Contributing

We welcome contributions! Here's how you can help improve this project:

### Adding New Scanners

1. **Create a new scanner file** in `internal/scanner/` (e.g., `clamav_scanner.go`)
2. **Implement the Scanner interface**:
   ```go
   type Scanner interface {
       Name() string
       Enabled() bool
       Scan(ctx context.Context, sc *ScanContext) error
   }
   ```
3. **Add configuration** in `internal/config/config.go`
4. **Register the scanner** in the engine factory
5. **Add tests** for your scanner
6. **Update documentation** in README.md

### Adding New Reporters

1. **Create a new reporter file** in `internal/reporter/` (e.g., `slack_reporter.go`)
2. **Implement the Reporter interface**:
   ```go
   type Reporter interface {
       Report(ctx context.Context, sc *scanner.ScanContext) error
   }
   ```
3. **Add configuration** in `internal/config/config.go`
4. **Register the reporter** in the factory
5. **Add tests** for your reporter
6. **Update documentation** in README.md

### General Contribution Steps

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`go test ./...`)
6. Format your code (`go fmt ./...`)
7. Submit a pull request

### Future Works / Contribution Ideas

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

**Other Improvements:**
- Performance optimizations
- Better error handling
- Additional configuration options
- Documentation improvements
- Docker improvements

## Support

For issues and questions, please open an issue on the repository or you can contact me by email
