# The SQLite driver is cgo, which shapes this whole file.
#
# A build without cgo links a go-sqlite3 stub that compiles cleanly and panics at
# startup with "requires cgo to work. This is a stub" — so CGO_ENABLED=1 is not
# optional, and neither is a C toolchain in the builder.
FROM golang:1.25-alpine AS builder

# gcc and musl-dev are what cgo needs. Without them the build fails with
# 'C compiler "gcc" not found', which is how this Dockerfile shipped broken.
RUN apk add --no-cache gcc musl-dev git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# -trimpath and -s -w keep the binary small and reproducible. No -a: rebuilding
# every dependency from scratch buys nothing and costs minutes.
RUN CGO_ENABLED=1 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/s3scanner ./cmd/s3scanner

# The dashboard ships in the same image, selected by overriding the command.
# One image rather than two: they share the config and the Finding type, so a
# single build cannot drift between what writes findings and what reads them.
RUN CGO_ENABLED=1 GOOS=linux go build \
      -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/s3nitor-dashboard ./cmd/s3nitor-dashboard

# The async collector, likewise. A third runtime rather than a goroutine inside
# the scanner: it waits on somebody else's analysis and uses almost nothing,
# while the scanner is bounded by bytes in flight and CPU. Sharing a process
# would make the scanner's memory limit cover both, and restarting one would
# interrupt the other.
RUN CGO_ENABLED=1 GOOS=linux go build \
      -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/s3nitor-async ./cmd/s3nitor-async

# Prove the binary can open a database before it ships. A green build is not
# evidence of a working binary here: the cgo failure mode only appears at
# runtime, and this is the cheapest place to catch a regression.
RUN /out/s3scanner --help >/dev/null 2>&1 || true
RUN DB_DRIVER=sqlite3 DB_DSN=/tmp/probe.db \
    S3_BUCKET=probe S3_ENDPOINT=http://127.0.0.1:1 \
    S3_ACCESS_KEY=x S3_SECRET_KEY=x \
    AWS_EC2_METADATA_DISABLED=true AWS_REGION=us-east-1 METRICS_ADDR= \
    /out/s3scanner 2>&1 | tee /tmp/probe.log; \
    if grep -q "CGO_ENABLED=0" /tmp/probe.log; then \
      echo "FATAL: built without cgo, the sqlite driver is a stub"; exit 1; fi; \
    if grep -q "failed init DB" /tmp/probe.log; then \
      echo "FATAL: the binary cannot open its database"; exit 1; fi

# ---------------------------------------------------------------------------
FROM alpine:latest

# yara is a runtime dependency of the YARA scanner, which shells out to it. It
# self-disables when the binary is missing, so leaving it out would silently
# reduce coverage rather than fail — better to ship it.
RUN apk --no-cache add ca-certificates tzdata yara && \
    addgroup -g 1001 -S s3nitor && \
    adduser -u 1001 -S s3nitor -G s3nitor

WORKDIR /app
COPY --from=builder /out/s3scanner .
COPY --from=builder /out/s3nitor-dashboard .
COPY --from=builder /out/s3nitor-async .
COPY --from=builder /app/rules ./rules

RUN chown -R s3nitor:s3nitor /app

# Numeric, not the name. With `runAsNonRoot: true` a kubelet has to prove the
# user is not root before starting the container, and it cannot resolve a name
# against the image's /etc/passwd — it fails with "image has non-numeric user"
# and never starts.
USER 1001:1001

# 8080 scanner metrics, 8081 dashboard.
EXPOSE 8080 8081

ENTRYPOINT ["./s3scanner"]
