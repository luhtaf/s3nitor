#!/usr/bin/env bash
#
# Seed a bucket with a defined object-size distribution.
#
# The workload definition is the first-class thing here. Benchmark numbers are
# determined entirely by object sizes, arrival rate and which scanners run, so a
# result quoted without them cannot be reproduced or compared against anything.
#
# Usage:
#   ./seed.sh <bucket> <count> <size>
#   ./seed.sh s3nitor-bench 500 64KB
#
# Sizes accept the same spellings as the app: 64KB, 10MB, 1GB.

source "$(dirname "${BASH_SOURCE[0]}")/../integration/lib.sh"

BUCKET_NAME="${1:-s3nitor-bench}"
COUNT="${2:-100}"
SIZE="${3:-64KB}"

MINIO_SVC="${MINIO_SVC:-s3nitor-test-minio}"
MINIO_PORT="${MINIO_PORT:-9000}"
MINIO_SECRET="${MINIO_SECRET:-s3nitor-test-minio-creds}"
MC_POD=s3nitor-bench-mc

[ "${KEEP_POD:-0}" = "1" ] || trap 'cleanup_tools "$MC_POD"; rm -rf "$WORK_DIR"' EXIT

mc()  { kubectl exec -n "$NS" "$MC_POD" -- mc --no-color "$@"; }
mci() { kubectl exec -i -n "$NS" "$MC_POD" -- mc --no-color "$@"; }
read_secret() { kubectl get secret "$1" -n "$NS" -o "jsonpath={.data.$2}" 2>/dev/null | base64 -d; }

# to_bytes mirrors config.ParseBytes so the harness and the app agree on what
# "64KB" means. Powers of two, matching how container limits are reasoned about.
to_bytes() {
  local raw="${1^^}" mult=1 num
  case "$raw" in
    *KIB|*KB|*K) mult=1024;        num="${raw%%[KMG]*}" ;;
    *MIB|*MB|*M) mult=1048576;     num="${raw%%[KMG]*}" ;;
    *GIB|*GB|*G) mult=1073741824;  num="${raw%%[KMG]*}" ;;
    *B)          mult=1;           num="${raw%B}" ;;
    *)           mult=1;           num="$raw" ;;
  esac
  awk -v n="$num" -v m="$mult" 'BEGIN{printf "%d", n*m}'
}

step "Preflight"
kubectl version --request-timeout=10s >/dev/null 2>&1 || fail "context '$KCTX' nggak reachable"
ensure_test_stack
require_svc "$MINIO_SVC"

step "Toolbox"
spawn_tool "$MC_POD" "minio/mc:latest"
U="$(read_secret "$MINIO_SECRET" MINIO_ROOT_USER)"
P="$(read_secret "$MINIO_SECRET" MINIO_ROOT_PASSWORD)"
[ -n "$U" ] && [ -n "$P" ] || fail "kredensial nggak kebaca dari '$MINIO_SECRET'"
mc alias set myminio "http://$MINIO_SVC:$MINIO_PORT" "$U" "$P" >/dev/null || fail "mc alias ditolak"
ok "mc terhubung"

step "Workload"
BYTES="$(to_bytes "$SIZE")"
[ "$BYTES" -gt 0 ] || fail "ukuran '$SIZE' tidak valid"
note "bucket=$BUCKET_NAME count=$COUNT size=$SIZE ($BYTES byte) total=$((BYTES*COUNT)) byte"

mc mb --ignore-existing "myminio/$BUCKET_NAME" >/dev/null
mc rm --recursive --force "myminio/$BUCKET_NAME" >/dev/null 2>&1 || true

# One payload reused for every object. Content is irrelevant to the sizing
# question — what is being measured is how many bytes move and how many objects
# there are, not what is inside them.
head -c "$BYTES" /dev/urandom > "$WORK_DIR/payload.bin"

step "Uploading $COUNT objects"
for i in $(seq 1 "$COUNT"); do
  mci pipe "myminio/$BUCKET_NAME/obj-$(printf '%06d' "$i").bin" < "$WORK_DIR/payload.bin" >/dev/null \
    || fail "gagal upload objek $i"
  if [ $((i % 50)) -eq 0 ]; then note "  $i/$COUNT"; fi
done
ok "$COUNT objek terunggah"

step "Ringkasan"
cat <<EOF
  bucket          $BUCKET_NAME
  objek           $COUNT × $SIZE
  total byte      $((BYTES*COUNT))

  Jalankan sweep dengan:
    ./test/bench/sweep.sh $BUCKET_NAME
EOF
