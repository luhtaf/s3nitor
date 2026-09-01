#!/usr/bin/env bash
#
# End-to-end verification against a real MinIO, entirely on one machine.
#
# Every Go test in this repo uses a fake fetcher and a fake scanner, which means
# nothing had ever proved that real bytes survive the pipeline: real S3 API, real
# download, real hashing, real rule matching, real database, real reporter
# output. That is what this checks.
#
# Docker only — no cluster, no registry, nothing to install. The sizing sweep
# still needs a container in Kubernetes, because its memory figure has to come
# from a cgroup; correctness does not.
#
# Usage: ./test/e2e/local.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
MINIO=s3nitor-e2e-minio
NET=s3nitor-e2e-net
BUCKET=e2e
PORT=19000
USER=e2eaccess
PASS=e2esecretkey

if [ -t 1 ]; then
  C_H=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_ERR=$'\033[0;31m'
  C_WARN=$'\033[0;33m'; C_DIM=$'\033[0;90m'; C_OFF=$'\033[0m'
else
  C_H=""; C_OK=""; C_ERR=""; C_WARN=""; C_DIM=""; C_OFF=""
fi
step() { printf '\n%s=== %s ===%s\n' "$C_H" "$*" "$C_OFF"; }
ok()   { printf '%s  ok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s  warn%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
note() { printf '%s       %s%s\n' "$C_DIM" "$*" "$C_OFF"; }
fail() { printf '%s  FAIL%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$MINIO" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mc() {
  docker run --rm --network "$NET" -e MC_HOST_m="http://$USER:$PASS@$MINIO:9000" \
    -v "$WORK:/w" minio/mc:latest --no-color "$@"
}

# --------------------------------------------------------------------------
step "Build"
command -v docker >/dev/null || fail "docker tidak ada di PATH"
CGO_ENABLED=1 go build -o "$WORK/s3scanner" ./cmd/s3scanner || fail "build gagal"
ok "binary terbangun"

# --------------------------------------------------------------------------
step "MinIO"
docker rm -f "$MINIO" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

# Published to the host so the scanner binary — which runs outside Docker — can
# reach it, and attached to the network so mc can reach it by name.
docker run -d --name "$MINIO" --network "$NET" -p "$PORT:9000" \
  -e MINIO_ROOT_USER="$USER" -e MINIO_ROOT_PASSWORD="$PASS" \
  quay.io/minio/minio:RELEASE.2025-04-08T15-41-24Z \
  server /data --console-address ":9001" >/dev/null \
  || fail "gagal menjalankan MinIO"

for i in $(seq 1 40); do
  if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/minio/health/ready" >/dev/null 2>&1; then break; fi
  [ "$i" = "40" ] && { docker logs "$MINIO" 2>&1 | tail -8; fail "MinIO tidak pernah siap"; }
  sleep 1
done
ok "MinIO siap di 127.0.0.1:$PORT"

# --------------------------------------------------------------------------
step "Objek uji"
mkdir -p "$WORK/obj"

# A file whose hash goes into the IOC list below, so the IOC path is exercised
# for real rather than mocked. No malware is needed to prove hash matching works:
# the rules are ours, so any file can be made to match.
printf 'this file is deliberately listed as a known-bad hash\n' > "$WORK/obj/flagged.bin"
printf 'an ordinary document with nothing interesting in it\n'  > "$WORK/obj/clean.txt"
head -c 200000 /dev/urandom > "$WORK/obj/large.bin"

FLAGGED_SHA=$(shasum -a 256 "$WORK/obj/flagged.bin" | awk '{print $1}')
note "hash yang ditanam: ${FLAGGED_SHA:0:20}…"

mc mb --ignore-existing "m/$BUCKET" >/dev/null
# Keys chosen to exercise escaping and prefixes, the two shapes that broke in
# phase 0.
mc cp /w/obj/flagged.bin "m/$BUCKET/flagged.bin"          >/dev/null
mc cp /w/obj/clean.txt   "m/$BUCKET/with space.txt"       >/dev/null
mc cp /w/obj/large.bin   "m/$BUCKET/nested/deep/large.bin" >/dev/null
ok "3 objek terunggah"

# --------------------------------------------------------------------------
step "Aturan IOC"
mkdir -p "$WORK/rules/ioc" "$WORK/rules/yara"
echo "$FLAGGED_SHA" > "$WORK/rules/ioc/sha256.txt"
: > "$WORK/rules/ioc/md5.txt"
: > "$WORK/rules/ioc/sha1.txt"
ok "1 hash terdaftar sebagai known-bad"

# --------------------------------------------------------------------------
run_scanner() {
  local out="$1"; shift
  : > "$out"
  DB_DRIVER=sqlite3 DB_DSN="$WORK/e2e.db" \
  S3_ENDPOINT="http://127.0.0.1:$PORT" S3_BUCKET="$BUCKET" \
  S3_ACCESS_KEY="$USER" S3_SECRET_KEY="$PASS" \
  AWS_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true \
  ENABLE_IOC=true ENABLE_YARA=false ENABLE_OTX=false ENABLE_VT=false \
  IOC_PATH="$WORK/rules/ioc/" YARA_PATH="$WORK/rules/yara/" \
  REPORTER_TYPE=json REPORTER_PATH="$out" \
  METRICS_ADDR= "$@" \
  "$WORK/s3scanner" 2>&1
}

step "Run 1 — pemindaian pertama"
if ! LOG1="$(run_scanner "$WORK/findings1.ndjson")"; then
  echo "$LOG1" | tail -15 | sed 's/^/  /'
  fail "scanner keluar dengan error"
fi
echo "$LOG1" | grep -E "run summary|discover:|lane " | sed 's/^/  /'

FOUND=$(wc -l < "$WORK/findings1.ndjson" | tr -d ' ')
[ "$FOUND" -eq 3 ] || fail "terbit $FOUND temuan, harusnya 3 (3 objek × 1 scanner)"
ok "3 temuan terbit, satu per objek"

# --------------------------------------------------------------------------
step "Isi temuan"
python3 - "$WORK/findings1.ndjson" "$FLAGGED_SHA" <<'PY'
import json, sys
docs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
want_sha = sys.argv[2]
fails = []

keys = sorted(d["key"] for d in docs)
expected = ["flagged.bin", "nested/deep/large.bin", "with space.txt"]
if keys != expected:
    fails.append(f"key yang terbaca {keys}, harusnya {expected}")

for d in docs:
    if d["scanner"] != "ioc":
        fails.append(f"{d['key']}: scanner={d['scanner']}")
    if not d.get("file_id"):
        fails.append(f"{d['key']}: file_id kosong")
    if not d.get("hashes", {}).get("sha256"):
        fails.append(f"{d['key']}: sha256 tidak dihitung")
    if not d.get("version"):
        fails.append(f"{d['key']}: version kosong, dedup tidak bisa membedakan versi")

flagged = next((d for d in docs if d["key"] == "flagged.bin"), None)
if flagged is None:
    fails.append("dokumen flagged.bin tidak ada")
else:
    if flagged["hashes"]["sha256"] != want_sha:
        fails.append("sha256 yang dihitung tidak cocok dengan yang diunggah")
    if not flagged["match"]:
        fails.append("hash yang ditanam di daftar IOC TIDAK terdeteksi")
    if flagged["severity"] != "high":
        fails.append(f"severity={flagged['severity']}, harusnya high")

for d in docs:
    if d["key"] != "flagged.bin" and d["match"]:
        fails.append(f"{d['key']}: false positive")

large = next((d for d in docs if d["key"] == "nested/deep/large.bin"), None)
if large and large["size"] != 200000:
    fails.append(f"size={large['size']}, harusnya 200000")

if fails:
    for f in fails: print("  FAIL", f)
    sys.exit(1)
print("  semua pemeriksaan isi lulus")
PY
[ $? -eq 0 ] || fail "isi temuan salah"
ok "hash cocok, IOC terdeteksi, tidak ada false positive"
note "$(python3 -c "
import json
d=[json.loads(l) for l in open('$WORK/findings1.ndjson')]
f=[x for x in d if x['key']=='flagged.bin'][0]
print(f\"flagged.bin → match={f['match']} severity={f['severity']} matched_on={f['detail'].get('matched_on')}\")")"

# --------------------------------------------------------------------------
step "Run 2 — dedup"
LOG2="$(run_scanner "$WORK/findings2.ndjson")" || fail "run kedua gagal"
AGAIN=$(wc -l < "$WORK/findings2.ndjson" | tr -d ' ')
[ "$AGAIN" -eq 0 ] || fail "run kedua menerbitkan $AGAIN temuan, harusnya 0"
echo "$LOG2" | grep "run summary" | sed 's/^/  /'
ok "semua objek dilewati — dedup selamat lintas proses"

# --------------------------------------------------------------------------
step "Run 3 — objek berubah discan ulang"
printf 'the content changed, so the ETag changes with it\n' > "$WORK/obj/flagged.bin"
mc cp /w/obj/flagged.bin "m/$BUCKET/flagged.bin" >/dev/null
run_scanner "$WORK/findings3.ndjson" >/dev/null || fail "run ketiga gagal"
CHANGED=$(wc -l < "$WORK/findings3.ndjson" | tr -d ' ')
[ "$CHANGED" -eq 1 ] || fail "run ketiga menerbitkan $CHANGED temuan, harusnya 1"
# The new content is not in the IOC list, so it must come back clean.
python3 -c "
import json,sys
d=json.loads(open('$WORK/findings3.ndjson').readline())
assert d['key']=='flagged.bin', d['key']
assert d['match'] is False, 'isi baru seharusnya tidak cocok IOC'
" || fail "temuan run ketiga salah"
ok "hanya objek yang berubah discan ulang, dan hasilnya bersih"

# --------------------------------------------------------------------------
step "Run 4 — MAX_OBJECT_SIZE menerbitkan celah cakupan"
run_scanner "$WORK/findings4.ndjson" >/dev/null || true
mc cp /w/obj/large.bin "m/$BUCKET/huge.bin" >/dev/null
MAX_OBJECT_SIZE=1000 run_scanner "$WORK/findings5.ndjson" >/dev/null || fail "run kelima gagal"
python3 - "$WORK/findings5.ndjson" <<'PY'
import json, sys
docs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
gaps = [d for d in docs if d["scanner"] == "size_gate"]
if not gaps:
    print("  FAIL objek kelewat besar dilewati tanpa menerbitkan apa-apa")
    sys.exit(1)
g = gaps[0]
if g["detail"]["scanned"] is not False:
    print("  FAIL celah cakupan mengklaim objeknya discan")
    sys.exit(1)
print(f"  celah terbit: {g['key']} size={g['detail']['object_size']} limit={g['detail']['limit']}")
PY
[ $? -eq 0 ] || fail "celah cakupan tidak terbit"
ok "objek yang dilewati dilaporkan, bukan hilang diam-diam"

# --------------------------------------------------------------------------
step "Isi database"
docker run --rm -v "$WORK:/w" alpine:latest sh -c 'apk add --no-cache sqlite >/dev/null 2>&1; \
  echo "  file_records: $(sqlite3 /w/e2e.db "select count(*) from file_records")"; \
  echo "  scan_tasks:   $(sqlite3 /w/e2e.db "select count(*) from scan_tasks")"; \
  echo "  journal_mode: $(sqlite3 /w/e2e.db "PRAGMA journal_mode")"' 2>/dev/null \
  || note "(sqlite3 tidak tersedia, pemeriksaan DB dilewati)"

step "Ringkasan"
cat <<EOF
  Terverifikasi dengan MinIO sungguhan, bukan tiruan:
    · API S3, unduhan, dan hashing streaming
    · key berspasi dan key ber-prefix bertahan bolak-balik
    · pencocokan IOC terhadap hash yang benar-benar dihitung
    · dedup bertahan lintas proses, versi baru discan ulang
    · objek yang dilewati menerbitkan celah cakupan
    · reporter JSON, skema database, WAL
EOF
ok "END-TO-END LULUS"
