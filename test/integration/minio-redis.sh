#!/usr/bin/env bash
#
# Fase 0 — MinIO → Redis. Nol kode Go.
#
# Tujuannya membuktikan jalur event beneran nyala sebelum pipeline-nya dibangun,
# dan merekam payload asli sebagai fixture buat unit test decoder. Lingkupnya
# sengaja sempit: sampai event kebaca dan object bisa diambil balik. Nggak ada
# scanning, nggak ada reporting.
#
# Pertanyaan yang harus dijawab skrip ini (lihat plan, Fase 0):
#   1. Bentuk persis payload MinIO
#   2. Key-nya di-URL-encode atau nggak
#   3. Field mana yang layak dipakai jadi `Version` (ada ETag?)
#   4. `format=access` beneran RPUSH ke list?
#   5. Kalau consumer mati persis setelah BRPOP, event-nya hilang beneran?
#
# Pakai:  ./test/integration/minio-redis.sh
# Env:    NS, MINIO_SVC, REDIS_SVC, MINIO_USER, MINIO_PASS, REDIS_PASSWORD, KEEP_POD=1

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Default-nya nunjuk ke stack uji sekali-pakai, BUKAN MinIO/Redis bersama.
# Ngaktifin config notifikasi butuh restart MinIO, dan MinIO bersama dipakai ELK.
# Bisa diarahkan ke instance lain lewat env kalau memang diniatkan.
MINIO_SVC="${MINIO_SVC:-s3nitor-test-minio}"
REDIS_SVC="${REDIS_SVC:-s3nitor-test-redis}"
MINIO_PORT="${MINIO_PORT:-9000}"
REDIS_PORT="${REDIS_PORT:-6379}"
# Kredensial dibaca dari secret k8s, nggak pernah ditulis di skrip.
MINIO_SECRET="${MINIO_SECRET:-s3nitor-test-minio-creds}"
REDIS_KEY="${REDIS_KEY:-s3nitor-events}"
KEEP_STACK="${KEEP_STACK:-0}"

read_secret() {   # read_secret <secret> <key>
  kubectl get secret "$1" -n "$NS" -o "jsonpath={.data.$2}" 2>/dev/null | base64 -d
}

MC_POD=s3nitor-mc
RD_POD=s3nitor-redis
[ "${KEEP_POD:-0}" = "1" ] || trap 'cleanup_tools "$MC_POD" "$RD_POD"; rm -rf "$WORK_DIR"' EXIT

mc()  { kubectl exec -n "$NS" "$MC_POD" -- mc --no-color "$@"; }
mci() { kubectl exec -i -n "$NS" "$MC_POD" -- mc --no-color "$@"; }   # stdin
rd()  { kubectl exec -n "$NS" "$RD_POD" -- redis-cli -h "$REDIS_SVC" -p "$REDIS_PORT" ${REDIS_PASSWORD:+-a "$REDIS_PASSWORD"} --no-auth-warning "$@"; }

# --------------------------------------------------------------------------
step "Preflight"
command -v kubectl >/dev/null || fail "kubectl nggak ada di PATH"
kubectl version --request-timeout=10s >/dev/null 2>&1 || fail "cluster nggak reachable"
ok "context: $(kubectl config current-context), ns: $NS"
mkdir -p "$FIXTURE_DIR"

# --------------------------------------------------------------------------
step "Stack uji sekali-pakai"
ensure_test_stack
require_svc "$MINIO_SVC"
require_svc "$REDIS_SVC"

# --------------------------------------------------------------------------
step "Nyiapin pod toolbox"
spawn_tool "$MC_POD" "minio/mc:latest"
spawn_tool "$RD_POD" "redis:alpine"

rd PING >/dev/null 2>&1 || fail "Redis nggak balas PING. Kalau butuh password, setel REDIS_PASSWORD."
ok "redis $REDIS_SVC:$REDIS_PORT balas PING"

MINIO_USER="${MINIO_USER:-$(read_secret "$MINIO_SECRET" MINIO_ROOT_USER)}"
MINIO_PASS="${MINIO_PASS:-$(read_secret "$MINIO_SECRET" MINIO_ROOT_PASSWORD)}"
[ -n "$MINIO_USER" ] && [ -n "$MINIO_PASS" ] \
  || fail "kredensial nggak kebaca dari secret '$MINIO_SECRET'. Setel MINIO_USER/MINIO_PASS manual."
note "kredensial dibaca dari secret $MINIO_SECRET (user: ${MINIO_USER:0:3}***)"

mc alias set myminio "http://$MINIO_SVC:$MINIO_PORT" "$MINIO_USER" "$MINIO_PASS" >/dev/null \
  || fail "gagal set alias mc — kredensial ditolak MinIO"
ok "mc terhubung ke $MINIO_SVC:$MINIO_PORT"

# --------------------------------------------------------------------------
step "Bikin bucket uji"
mc mb --ignore-existing "myminio/$BUCKET" >/dev/null
mc rm --recursive --force "myminio/$BUCKET" >/dev/null 2>&1 || true
ok "bucket myminio/$BUCKET siap dan kosong"

# --------------------------------------------------------------------------
step "Target notifikasi Redis"

# Target dideklarasikan lewat env var di manifest (MINIO_NOTIFY_REDIS_*_PRIMARY),
# jadi sudah hidup sejak MinIO start — nggak ada `config set` + restart di sini.
# Lihat komentar panjang di manifests/test-stack.yaml soal kenapa jalur
# `mc admin config set` itu jebakan.
ARNS="$(mc admin info myminio --json 2>/dev/null \
        | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin).get("info",{}).get("sqsARN",[]) or []))' \
        2>/dev/null || true)"
[ -n "$ARNS" ] || fail "server nggak ngedaftarin satupun SQS ARN — env MINIO_NOTIFY_REDIS_* nggak kebaca"
ok "ARN terdaftar sejak startup: $ARNS"

QUEUE_DIR_OK=1

# ARN dipakai apa adanya dari server, JANGAN dirakit sendiri. Kalau target
# dideklarasikan lewat env (MINIO_NOTIFY_REDIS_..._PRIMARY), nama target di ARN
# ikut huruf besar sufiks env-nya — `arn:minio:sqs::PRIMARY:redis`, bukan
# `primary`. Nebak lowercase bikin event add ditolak "ARN does not exist".
ARN="$(awk '{print $1}' <<<"$ARNS")"
note "pakai ARN: $ARN"

ADD_OUT="$(mc event add "myminio/$BUCKET" "$ARN" --event put 2>&1 || true)"
if grep -qi "already exists\|successfully\|^$" <<<"$ADD_OUT"; then
  ok "aturan event terpasang"
else
  fail "gagal masang aturan event: $ADD_OUT"
fi

step "Aturan event yang aktif"
mc event list "myminio/$BUCKET" 2>&1 | head -5

# --------------------------------------------------------------------------
step "Kosongin list Redis biar hasilnya bersih"
rd DEL "$REDIS_KEY" >/dev/null
ok "$REDIS_KEY dikosongkan"

# --------------------------------------------------------------------------
step "Upload tiga PDF"
write_pdf "$WORK_DIR/mini.pdf"
LOCAL_SHA="$(sha_of "$WORK_DIR/mini.pdf")"
LOCAL_SIZE="$(wc -c < "$WORK_DIR/mini.pdf" | tr -d ' ')"
note "lokal: $LOCAL_SIZE byte, sha256 ${LOCAL_SHA:0:16}…"

# `mc pipe` baca stdin — jadi nggak perlu nyalin file ke dalam pod, dan nggak
# bergantung pada image mc punya base64/tar atau nggak.
for key in "$KEY_PLAIN" "$KEY_SPACE" "$KEY_NESTED"; do
  mci pipe "myminio/$BUCKET/$key" < "$WORK_DIR/mini.pdf" >/dev/null \
    || fail "gagal upload '$key'"
  ok "terupload: $key"
done

note "nunggu event nyampe Redis..."
for i in $(seq 1 20); do
  COUNT="$(rd LLEN "$REDIS_KEY" | tr -d '\r')"
  [ "${COUNT:-0}" -ge 3 ] && break
  sleep 1
done
COUNT="$(rd LLEN "$REDIS_KEY" | tr -d '\r')"
if [ "${COUNT:-0}" -lt 3 ]; then
  fail "cuma $COUNT event dari 3 yang diharapkan. Notifikasi nggak jalan — cek 'mc event list' dan log MinIO."
fi
ok "$COUNT event masuk ke list Redis (format=access = RPUSH terbukti)"

# --------------------------------------------------------------------------
step "Payload mentah"
PAYLOAD="$(rd LRANGE "$REDIS_KEY" 0 -1)"
printf '%s\n' "$PAYLOAD" | head -c 4000
echo

printf '%s' "$PAYLOAD" > "$FIXTURE_DIR/event-minio-redis.raw.json"
ok "fixture disimpan: test/fixtures/event-minio-redis.raw.json"

report_encoding "$PAYLOAD"

# --------------------------------------------------------------------------
step "Field yang dipakai buat Version"
if grep -qi '"eTag"' <<<"$PAYLOAD"; then
  ok "eTag ADA di payload → Version = eTag"
  note "$(grep -o '"eTag"[^,]*' <<<"$PAYLOAD" | head -3)"
else
  warn "eTag nggak ketemu → Version harus jatuh ke mtime/sequencer"
fi
grep -q '"size"' <<<"$PAYLOAD" && ok "size ada" || warn "size nggak ada di payload"

# --------------------------------------------------------------------------
step "Baca balik object lewat S3 API"
for key in "$KEY_PLAIN" "$KEY_SPACE" "$KEY_NESTED"; do
  kubectl exec -n "$NS" "$MC_POD" -- mc --no-color cat "myminio/$BUCKET/$key" > "$WORK_DIR/back.pdf" 2>/dev/null \
    || fail "gagal baca balik '$key'"
  got_sha="$(sha_of "$WORK_DIR/back.pdf")"
  got_size="$(wc -c < "$WORK_DIR/back.pdf" | tr -d ' ')"
  [ "$got_sha" = "$LOCAL_SHA" ] \
    || fail "'$key' beda isi: $got_size byte, sha ${got_sha:0:16}… (harusnya ${LOCAL_SHA:0:16}…)"
  ok "byte-identik: $key ($got_size byte)"
done

# --------------------------------------------------------------------------
step "Uji durabilitas: apa event hilang kalau consumer mati setelah BRPOP?"
# Ini pertanyaan paling menentukan di Fase 0. Kalau hilang, Redis nggak layak
# jadi antrian produksi dan Kafka harus dideploy.
BEFORE="$(rd LLEN "$REDIS_KEY" | tr -d '\r')"
POPPED="$(rd LPOP "$REDIS_KEY")"     # ambil, lalu sengaja TIDAK diproses
AFTER="$(rd LLEN "$REDIS_KEY" | tr -d '\r')"
note "sebelum=$BEFORE  sesudah=$AFTER  terambil=${#POPPED} byte"
if [ "${AFTER:-0}" -lt "${BEFORE:-0}" ]; then
  warn "EVENT HILANG PERMANEN. LPOP/BRPOP itu destruktif dan nggak ada ack —"
  warn "consumer yang mati setelah pop bakal ngilangin event itu selamanya."
  warn "→ Redis oke buat dev. Buat produksi butuh Kafka (offset commit) atau"
  warn "  Redis Streams + consumer group (XACK), yang BUKAN target bawaan MinIO."
  REDIS_DURABLE=0
else
  ok "event masih ada setelah pop — di luar dugaan, periksa manual"
  REDIS_DURABLE=1
fi

# --------------------------------------------------------------------------
step "Ringkasan"
cat <<EOF
  bucket           myminio/$BUCKET
  transport        redis list '$REDIS_KEY' (format=access, RPUSH)
  event terkirim   $COUNT / 3
  baca balik       3 / 3 byte-identik
  queue_dir        $([ "$QUEUE_DIR_OK" = "1" ] && echo "aktif (spool pas broker mati)" || echo "TIDAK aktif")
  ack              $([ "$REDIS_DURABLE" = "0" ] && echo "TIDAK ADA — event hilang kalau consumer crash" || echo "cek manual")
  fixture          test/fixtures/event-minio-redis.raw.json

  Yang boleh ditulis di README: MinIO + Redis = teruji buat notifikasi & baca bucket,
  dengan catatan tegas soal nggak adanya ack.
EOF
ok "minio-redis LULUS"
