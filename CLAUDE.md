# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`s3nitor` (module `github.com/luhtaf/s3nitor`, binary `s3scanner`) scans S3-compatible object storage for malicious content. Go 1.25 (floor set by `pgx v5.10`, upgraded for its CVEs). No Go test files exist yet — the shell suites under `test/integration/` need a live cluster.

Code comments and log messages are a mix of Indonesian and English — match the surrounding file rather than normalizing.

## Commands

```bash
make run                 # go run ./cmd/s3scanner/main.go
make build               # -> build/s3scanner, LDFLAGS injects main.Version from git describe
make test                # go test -v ./...   (no tests exist yet)
make fmt                 # go fmt ./...
make lint                # golangci-lint run
make release             # host-platform release binary only (see cgo note below)
make docker-build        # docker build -t s3scanner .
```

The image needs `gcc` and `musl-dev` in the builder stage — the alpine Go image
does not ship a C compiler, and without them the cgo build fails with
`C compiler "gcc" not found`. The Dockerfile also runs the binary against a real
SQLite file before the final stage, so a cgo regression fails the build rather
than shipping.

Images publish to `ghcr.io/luhtaf/s3nitor` via `.github/workflows/image.yml`.
The package is private until changed in the repository's package settings; a
private package needs an `imagePullSecret` in the cluster or pulls fail with
`ImagePullBackOff`.

Run a single test once tests exist: `go test -v -run TestName ./internal/scanner/`.

### cgo is mandatory — do not cross-compile

The SQLite driver (`mattn/go-sqlite3`) requires cgo. Go silently sets `CGO_ENABLED=0` whenever `GOOS`/`GOARCH` differ from the host without a cross-compiler, and go-sqlite3 then links a **stub that compiles cleanly but panics at startup**:

```
failed init DB: Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work
```

A green build is not evidence of a working binary. Multi-platform artifacts are built natively per-OS by `.github/workflows/release.yml`, which smoke-tests each one against a real SQLite file before publishing. Cutting a release is `git tag v0.1.0 && git push origin v0.1.0`.

Escape hatch if true cross-compilation is ever needed: swap `gorm.io/driver/sqlite` for `github.com/glebarez/sqlite` (pure Go, no cgo), at the cost of a different SQLite implementation.

`main.Version` is injected via `-ldflags -X` and printed at startup; keep the `var Version` declaration in `cmd/s3scanner/main.go` or the flag becomes a silent no-op again.

Configuration is entirely environment variables loaded via `godotenv` from `.env` (see `env.example`). There are no CLI flags. `.env` is gitignored — copy `env.example` to `.env` before running.

`CGO_ENABLED=1` is required for the SQLite driver (`mattn/go-sqlite3`), which is why the Dockerfile sets it explicitly.

## Architecture

Single-shot batch pipeline, not a daemon. `cmd/s3scanner/main.go` owns the entire orchestration — there is no separate service layer:

1. `config.Load()` reads every setting from env into one flat `*Config` struct that is passed to every constructor.
2. `s3fetcher.ListObjects` paginates the whole bucket into a slice up front (all metadata held in memory).
3. A buffered `jobs` channel sized to `len(objects)` feeds `WORKER_COUNT` goroutines (defaults to `runtime.NumCPU()`).
4. Each worker: DB dedup check → `fetcher.Download` to `os.TempDir()` → `engine.ProcessFile` → `rep.Report` → `db.UpsertFileRecord` → `os.Remove(localPath)`.
5. Signal trap cancels the shared `context.Context`; workers check `ctx.Done()` between jobs.

### Scanner engine (`internal/scanner`)

All scanners implement `Scanner` (`Name() / Enabled() / Scan(ctx, *ScanContext) error`) and mutate a shared `*ScanContext` in sequence. **Ordering is load-bearing**: `NewEngine` always registers `HashScanner` first because it populates `sc.Hashes`, which `IOCScanner` and `OTXScanner` read as their only input. A new hash-consuming scanner must be appended after it.

Scan errors are logged and swallowed inside `ProcessFile` — one failing scanner never aborts the others, and `ProcessFile` never returns a non-nil error today.

`Engine.Run` is vestigial (just blocks on ctx); `main.go` calls `ProcessFile` directly.

Scanner specifics:
- `YARAScanner` shells out to the `yara` binary (`YARA_CMD`) once per `.yar` file, parsing stdout. It self-disables in its constructor if the binary is missing or the rules dir has no `.yar` files — exit code 1 means "no match", not an error.
- `OTXScanner` is gated on `cfg.EnableOTX && cfg.S3Endpoint != ""` plus a non-empty API key.

### Reporters (`internal/reporter`)

`Build(cfg)` switches on `REPORTER_TYPE` (`json` | `elasticsearch` | `loki` | `prometheus`; empty falls back to JSON). One `Reporter` instance is shared across all workers, so any new reporter must be goroutine-safe — the existing JSON reporter is not (concurrent appends to the same file).

Each reporter independently builds the same `bucket/key/size/hashes/scan_time/results` envelope; changing the output shape means editing all of them.

### Persistence (`internal/db`)

GORM with sqlite3/mysql/postgres selected by `DB_DRIVER`. `FileRecord` is keyed by `(bucket, object_key)` for re-scan avoidance.

Note the skip logic in `main.go` compares `record.ETag == j.ETag && !record.UpdatedAt.Before(j.LastModified)`, while `UpsertFileRecord` compares `existing.UpdatedAt.Equal(record.UpdatedAt)` against a `record.UpdatedAt` the caller never sets (it sets `ScanTime`). These two paths disagree; be deliberate when touching either.

## Extension points

- **New scanner**: implement `Scanner` in `internal/scanner/`, add the config field in `internal/config/config.go`, register in `NewEngine` (after `HashScanner` if it needs hashes), write results into `sc.Results[Name()]`.
- **New reporter**: implement `Reporter` in `internal/reporter/`, add config fields, add a case to `Build`.

## Rules directories

`rules/ioc/{md5,sha1,sha256}.txt` — one hash per line, missing files are skipped with a log line. `rules/yara/*.yar` — only the `.yar` extension is globbed (`.yara` is not picked up).
