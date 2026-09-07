# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`s3nitor` (module `github.com/luhtaf/s3nitor`, binary `s3scanner`) scans S3-compatible object storage for malicious content. Go 1.25 (floor set by `pgx v5.10`, upgraded for its CVEs). The shell suites under `test/integration/` and `test/bench/` need a live cluster; everything else runs with `go test`.

Code comments and log messages are a mix of Indonesian and English — match the surrounding file rather than normalizing.

## Commands

```bash
make run                 # go run ./cmd/s3scanner/main.go
make build               # -> build/s3scanner, LDFLAGS injects main.Version from git describe
make test                # go test -v ./...
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

Run one test: `go test -race -run TestName ./internal/pipeline/`. Use `-race` for
anything touching the pipeline — the limiters and the payload refcount are where
concurrency bugs would hide, and several were caught that way.

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

Single-shot batch job, not a daemon. `cmd/s3scanner/main.go` is wiring only; the
work lives in `internal/pipeline`.

```
discover ──► fetch+hash ──► dispatch ──┬─► ioc  ────────┐
1 goroutine   byte budget   file×scanner├─► yara ───────┼─► publish
dedup batched + conn slots              └─► virustotal ─┘   batch+flush
                                                            1 goroutine
```

**A stage boundary exists to separate different resource profiles.** Discovery
waits on pagination, fetch on the network while holding bytes, local scanners on
CPU, intel scanners on somebody else's quota. One bound across all of them would
have to be chosen for the worst case.

### Limiters (`internal/pipeline/limiter.go`)

All satisfy `Limiter`: `Acquire(ctx, weight) (release func(Outcome), error)`.

- **`byteLimiter`** is the global brake and the one to be careful with. It is
  acquired in fetch and released only after the analyze stage deletes the temp
  file, because the bytes are resident that whole time — first in network
  buffers, then on disk. Releasing it when the transfer ends (an earlier bug)
  removed the backpressure entirely: fetch stopped backing off and filled the
  disk while the accounting claimed the budget was free.
- **`connLimiter`** bounds concurrent transfers, a shorter span.
- **`cpuLimiter`** is shared by every local lane. One per lane would permit a
  multiple of the intended parallelism.
- Spill lanes get their own `RateLimiter`, because "four requests per minute"
  cannot be expressed as a concurrency limit.

An object larger than the whole budget is **clamped**, not rejected —
`semaphore.Weighted` blocks forever on an unsatisfiable request.

### Scanners (`internal/scanner`, `internal/intel`)

```go
Scan(ctx context.Context, in *ScanInput) (Result, error)
```

`ScanInput` is read-only and shared; each scanner returns its own `Result`. There
is no shared mutable state, so registration order carries no meaning and lanes
run concurrently. Hashing is not a scanner — it is an `io.Writer` teed into the
download (`internal/hashing`), so hashes arrive as input.

`NeedsPayload()` decides two things: whether the payload refcount holds the temp
file open for this scanner, and whether a retried task must re-download. Only
YARA needs the bytes; IOC and the intel lookups need only hashes.

`NewEngine` builds the local scanners. The intel ones are composed in `main.go`
instead — they need the cache, and wiring them inside `scanner` would make
`scanner` import `intel` while `intel` imports `scanner`.

### Sync versus async

A separate axis from the lane policy below. The policy answers "the queue is
full, now what"; the mode answers "does the verdict come back from the call we
just made".

`ModeSync` returns a `Result` within `Timeout()`. `ModeAsync` starts work
elsewhere and returns a `*PendingError` carrying a resume token. Both use the
same error: an async scanner returns it immediately, a sync one only when its
deadline passes with work already in flight.

**A timeout is a handoff, not a loss.** Submitting to a sandbox has already paid
for the upload; abandoning it on a deadline would throw that away and re-send
the same bytes on retry. Returning the token instead keeps the external analysis
running and lets `s3nitor-async` resume it by polling.

`Resumable.Poll(ctx, token)` deliberately takes no `ScanInput`: the object went
to the sandbox at submit time, so resuming needs the token, never the bytes.
That is why the async worker holds no S3 credentials and why the payload is
released the moment a scan is handed off.

**Nothing is published for a pending scan.** A placeholder document would mean
every consumer had to know that `match:false` sometimes means "not answered
yet", and the one that forgets reads an unfinished detonation as a clean file.

### Block versus spill

A full queue is handled by **how long the wait is**, not how slow the scanner is.
CPU saturation clears in seconds, so those lanes block upstream. An API quota
clears in hours, so those lanes write the task to `scan_tasks` and move on —
otherwise a four-per-minute VirusTotal key would cap the whole pipeline at four
files per minute. `SPILL_SCANNERS` names which.

### Publishing

One document per **(file × scanner)**, not per file. Correlation happens at query
time on `file_id`, so a slow scanner never delays a fast one's result.

Flush triggers, whichever fires first: batch size, byte ceiling, or an interval
measured from the first document entering an empty batch (so no document waits
longer than one interval). A partial batch is drained on shutdown. A document
that alone exceeds the byte ceiling is sent on its own.

**Ordering is load-bearing:** records are written only *after* the sink accepts
the batch. Reversed, a crash in between loses those findings permanently — the
record claims the object was handled, so it is never queued again. That is safe
only because `Finding.DocID()` is deterministic, which turns a replay into an
overwrite.

### Async collection (`internal/async`, `cmd/s3nitor-async`)

A second topic (`ASYNC_TOPIC`) and a second binary. Two topics because the
messages differ in lifetime: an event is consumed in milliseconds, a
continuation may be re-queued for hours, and a Kafka partition delivers in
order — the slow message does not step aside.

The worker has two ways in, and they are not redundant. Kafka makes collection
prompt; the sweeper over `scan_tasks` makes it certain, because a message can be
lost to a broker outage or a retention window that expires mid-analysis. **The
ledger is the source of truth and Kafka is an accelerator** — which is why
`handoff` writes the row before publishing, and why lister mode can enable a
sandbox without acquiring a broker dependency.

`EnqueueContinuation` does not increment `Attempts`: polling a running analysis
is not a failed attempt, and counting it as one lets `PENDING_MAX_ATTEMPTS`
abandon a sandbox job purely for being slow.

`ASYNC_MAX_AGE` abandons an analysis that never finishes, publishing a document
that says so. Left polling, the task stays pending and publishes nothing — and
nothing is indistinguishable from clean.

### Persistence (`internal/db`)

- **`FileRecord`** keyed by `FileID = sha256(bucket ‖ key ‖ version)`. Folding the
  version into the key means a row's existence already proves this exact content
  was scanned — there is no second timestamp comparison to disagree with it.
  `version` is the ETag where the storage has one; SeaweedFS has none.
- **`ScanTask`** is one row per (file × scanner): pending queue, retry ledger and
  dedup key at once. It holds no results. Leases rather than a running flag, so a
  dead process does not strand rows and a healthy replica is not robbed.
- **`IntelCache`** is keyed by **content hash**, not FileID: a threat-intel lookup
  is a pure function of the bytes, so the same payload under twenty keys costs one
  request. A 404 is cached too — it is an answer.

SQLite needs `_journal_mode=WAL` and a busy timeout, which `NewDB` adds to the
DSN; without them a second writer fails instead of waiting.

### Sources (`internal/source`)

`SOURCE_MODE=lister|event`. The pipeline consumes a **stream**, so an event source
that never ends works the same as a finite listing — but only because every
batching stage flushes on a timer as well as on size. Discovery batches its dedup
lookups, and a size-only trigger left a partial batch sitting forever under an
endless source: acknowledged to the broker, counted as listed, never scanned, and
silent because nothing failed. Any new batching added here needs the same pair of
triggers, and a test that does **not** close the channel — `stream()` in the tests
closes it, which is exactly why the whole suite missed this.

Event mode is `Transport` (redis, kafka) plus `Decoder` (minio). These vary
independently — but less than expected: the same MinIO instance wraps the identical
event as `{"Records":[…]}` for Kafka and `[{"Event":[…]}]` for Redis, so the
decoder sniffs the envelope rather than the vendor.

Two measured quirks the decoder tests pin down: keys need `url.QueryUnescape`, not
`PathUnescape` (a space arrives as `+`, and `PathUnescape` leaves it, returning a
key that does not exist without an error); and streamed uploads arrive as
`s3:ObjectCreated:CompleteMultipartUpload`, not `:Put`.

`S3_ENDPOINT` forces `UsePathStyle` — the default virtual-hosted style puts the
bucket in the hostname, which cannot resolve against a custom endpoint.

## Extension points

- **New scanner**: implement `Scanner`, add config, register in `NewEngine` (or
  compose in `main.go` if it needs the DB). Add its name to `SPILL_SCANNERS` if it
  waits on something external.
- **New reporter**: implement `Reporter`; optionally `BatchReporter` if the sink
  has a bulk API. Add a case to `Build`.
- **New event format**: implement `Decoder`, add a case to `buildDecoder`. Test it
  against a captured payload in `test/fixtures/`, not against a hand-written one.

## Verifying changes

```bash
go test -race ./...        # 54 tests, no infrastructure needed
./test/e2e/local.sh        # real MinIO in Docker, no cluster
```

`test/e2e/local.sh` is the one that catches integration bugs: every Go test uses a
fake fetcher, so nothing else proves real bytes survive the pipeline.

## Rules directories

`rules/ioc/{md5,sha1,sha256}.txt` — one hash per line, missing files are skipped with a log line. `rules/yara/*.yar` — only the `.yar` extension is globbed (`.yara` is not picked up).
