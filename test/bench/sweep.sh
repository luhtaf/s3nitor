#!/usr/bin/env bash
#
# Sweep pipeline limits and record what each setting actually costs.
#
# Runs s3nitor as a Kubernetes Job so the memory figure comes from a cgroup —
# the same number the OOM killer compares against limits.memory. Measuring on a
# laptop would report something entirely different and useless for sizing.
#
# Each run starts from an empty database, otherwise dedup would make every run
# after the first scan nothing.
#
# Usage:
#   ./sweep.sh <bucket> [image]
#
# Output: a CSV on stdout and a table at the end, ready to paste into the article.

source "$(dirname "${BASH_SOURCE[0]}")/../integration/lib.sh"

BUCKET_NAME="${1:-s3nitor-bench}"
IMAGE="${2:-${BENCH_IMAGE:-}}"
MINIO_SVC="${MINIO_SVC:-s3nitor-test-minio}"
MINIO_SECRET="${MINIO_SECRET:-s3nitor-test-minio-creds}"
JOB=s3nitor-bench-run
CSV="${CSV:-$REPO_ROOT/test/bench/results.csv}"

[ -n "$IMAGE" ] || fail "set BENCH_IMAGE atau berikan image sebagai argumen kedua.
  Bangun dan dorong dulu:
    docker build -t <registry>/s3nitor:bench . && docker push <registry>/s3nitor:bench"

# --------------------------------------------------------------------------
# The sweep. Each row is one run: a label, then the environment that defines it.
#
# Deliberately one variable at a time. Changing two at once produces a table
# nobody can draw a conclusion from.
# --------------------------------------------------------------------------
SWEEP=(
  # label|FETCH_BYTE_BUDGET|FETCH_MAX_CONNS|ANALYZE_CPU_LIMIT
  "baseline|512MB|16|0"

  # Does the byte budget bound memory, or does connection count?
  "budget-64MB|64MB|16|0"
  "budget-128MB|128MB|16|0"
  "budget-256MB|256MB|16|0"
  "budget-512MB|512MB|16|0"

  # Same budget, more transfers. If memory tracks this rather than the budget,
  # the whole premise of the redesign is wrong.
  "conns-4|256MB|4|0"
  "conns-16|256MB|16|0"
  "conns-64|256MB|64|0"

  # Where does throughput stop improving? That point is limits.cpu.
  "cpu-1|256MB|16|1"
  "cpu-2|256MB|16|2"
  "cpu-4|256MB|16|4"
  "cpu-8|256MB|16|8"
)

run_one() {
  local label="$1" budget="$2" conns="$3" cpu="$4"

  kubectl delete job "$JOB" -n "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true

  # A fresh database per run. Reusing one would let dedup skip everything after
  # the first run and every later row would measure an empty scan.
  kubectl create job "$JOB" -n "$NS" --image="$IMAGE" --dry-run=client -o json 2>/dev/null \
    | python3 - "$label" "$budget" "$conns" "$cpu" "$MINIO_SVC" "$BUCKET_NAME" "$MINIO_SECRET" <<'PY' \
    | kubectl apply -n "$NS" -f - >/dev/null
import json, sys
label, budget, conns, cpu, minio, bucket, secret = sys.argv[1:8]
job = json.load(sys.stdin)
job["spec"]["backoffLimit"] = 0
c = job["spec"]["template"]["spec"]["containers"][0]
c["imagePullPolicy"] = "IfNotPresent"
c["env"] = [
    {"name": "DB_DRIVER", "value": "sqlite3"},
    {"name": "DB_DSN", "value": "/tmp/bench.db"},
    {"name": "S3_ENDPOINT", "value": f"http://{minio}:9000"},
    {"name": "S3_BUCKET", "value": bucket},
    {"name": "AWS_REGION", "value": "us-east-1"},
    {"name": "AWS_EC2_METADATA_DISABLED", "value": "true"},
    {"name": "REPORTER_TYPE", "value": "json"},
    # stdout, so publishing costs the same in every row instead of varying with
    # a sink nobody is measuring
    {"name": "REPORTER_PATH", "value": ""},
    {"name": "ENABLE_IOC", "value": "true"},
    {"name": "ENABLE_YARA", "value": "false"},
    {"name": "ENABLE_OTX", "value": "false"},
    {"name": "METRICS_ADDR", "value": ""},
    {"name": "FETCH_BYTE_BUDGET", "value": budget},
    {"name": "FETCH_MAX_CONNS", "value": conns},
    {"name": "ANALYZE_CPU_LIMIT", "value": cpu},
    {"name": "S3_ACCESS_KEY", "valueFrom": {"secretKeyRef": {"name": secret, "key": "MINIO_ROOT_USER"}}},
    {"name": "S3_SECRET_KEY", "valueFrom": {"secretKeyRef": {"name": secret, "key": "MINIO_ROOT_PASSWORD"}}},
]
# No memory limit during the sweep: the point is to discover what it needs, and
# a limit would either mask the peak or kill the run before it reports one.
c["resources"] = {"requests": {"cpu": "500m", "memory": "128Mi"}}
job["spec"]["template"]["spec"]["restartPolicy"] = "Never"
job["spec"]["template"]["metadata"] = {"labels": {"app.kubernetes.io/part-of": "s3nitor-test"}}
json.dump(job, sys.stdout)
PY

  if ! kubectl wait --for=condition=complete "job/$JOB" -n "$NS" --timeout=900s >/dev/null 2>&1; then
    warn "$label: job tidak selesai"
    kubectl logs -n "$NS" "job/$JOB" --tail=15 2>/dev/null | sed 's/^/    /'
    return 1
  fi

  local line
  line="$(kubectl logs -n "$NS" "job/$JOB" 2>/dev/null | grep "run summary:" | tail -1)"
  [ -n "$line" ] || { warn "$label: tidak ada baris ringkasan"; return 1; }

  local scanned duration rate peak source
  scanned="$(sed -n 's/.*scanned=\([0-9]*\).*/\1/p' <<<"$line")"
  duration="$(sed -n 's/.*duration=\([^ ]*\).*/\1/p' <<<"$line")"
  rate="$(sed -n 's/.*rate=\([0-9.]*\).*/\1/p' <<<"$line")"
  peak="$(sed -n 's/.*peak_rss=\([0-9]*\).*/\1/p' <<<"$line")"
  source="$(sed -n 's/.*peak_rss_source=\([a-zA-Z]*\).*/\1/p' <<<"$line")"

  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$label" "$budget" "$conns" "$cpu" "$scanned" "$duration" "$rate" "$peak" >> "$CSV"

  printf '  %-14s budget=%-7s conns=%-3s cpu=%-2s  %5s objek  %8s  %6s/s  peak %s (%s)\n' \
    "$label" "$budget" "$conns" "$cpu" "$scanned" "$duration" "$rate" \
    "$(numfmt --to=iec "$peak" 2>/dev/null || echo "$peak")" "$source"
}

# --------------------------------------------------------------------------
step "Preflight"
kubectl version --request-timeout=10s >/dev/null 2>&1 || fail "context '$KCTX' nggak reachable"
require_svc "$MINIO_SVC"
ok "context: $KCTX, image: $IMAGE"

echo "label,budget,conns,cpu,scanned,duration,rate_per_s,peak_rss_bytes" > "$CSV"

step "Sweep (${#SWEEP[@]} run)"
for row in "${SWEEP[@]}"; do
  IFS='|' read -r label budget conns cpu <<<"$row"
  run_one "$label" "$budget" "$conns" "$cpu" || true
done

kubectl delete job "$JOB" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true

step "Hasil"
column -s, -t < "$CSV"
echo
ok "CSV: $CSV"
