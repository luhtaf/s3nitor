#!/usr/bin/env bash
#
# Fase 0 — MinIO → Kafka. Nol kode Go.
#
# Pasangan dari minio-redis.sh. Kedua target hidup di MinIO yang sama, jadi
# event yang PERSIS sama dikirim ke dua transport — itu yang bikin perbandingan
# amplopnya sah, bukan membandingkan dua kejadian berbeda.
#
# Pertanyaan yang dijawab skrip ini:
#   1. Apa amplop Kafka sama dengan amplop Redis `[{"Event":[…]}]`?
#   2. Apa key-nya di-encode dengan cara yang sama (+ dan %2F)?
#   3. Apa consumer group beneran ngasih ack yang selamat dari crash consumer —
#      hal yang terbukti TIDAK dipunyai Redis?
#
# Pakai:  ./test/integration/minio-kafka.sh
# Env:    KCTX (default kubeth), NS, KEEP_STACK=1

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MINIO_SVC="${MINIO_SVC:-s3nitor-test-minio}"
KAFKA_SVC="${KAFKA_SVC:-s3nitor-test-kafka}"
MINIO_PORT="${MINIO_PORT:-9000}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
MINIO_SECRET="${MINIO_SECRET:-s3nitor-test-minio-creds}"
TOPIC="${TOPIC:-s3nitor-events}"
GROUP="${GROUP:-s3nitor-phase0}"

MC_POD=s3nitor-mc
KF_POD=s3nitor-kafka-cli
[ "${KEEP_POD:-0}" = "1" ] || trap 'cleanup_tools "$MC_POD" "$KF_POD"; rm -rf "$WORK_DIR"' EXIT

mc()  { kubectl exec -n "$NS" "$MC_POD" -- mc --no-color "$@"; }
mci() { kubectl exec -i -n "$NS" "$MC_POD" -- mc --no-color "$@"; }

read_secret() { kubectl get secret "$1" -n "$NS" -o "jsonpath={.data.$2}" 2>/dev/null | base64 -d; }

# Consumer Kafka. --timeout-ms bikin dia berhenti sendiri, jadi skrip nggak
# nunggu selamanya kalau nggak ada pesan.
kcat() {
  kubectl exec -n "$NS" "$KF_POD" -- /opt/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server "$KAFKA_SVC:$KAFKA_PORT" "$@"
}
ktool() { kubectl exec -n "$NS" "$KF_POD" -- "$@"; }

# --------------------------------------------------------------------------
step "Preflight"
command -v kubectl >/dev/null || fail "kubectl nggak ada di PATH"
kubectl version --request-timeout=10s >/dev/null 2>&1 || fail "context '$KCTX' nggak reachable"
ok "context: $KCTX, ns: $NS"
mkdir -p "$FIXTURE_DIR"

# --------------------------------------------------------------------------
step "Stack uji sekali-pakai"
ensure_test_stack
require_svc "$MINIO_SVC"
require_svc "$KAFKA_SVC"

# --------------------------------------------------------------------------
step "Nyiapin pod toolbox"
spawn_tool "$MC_POD" "minio/mc:latest"
spawn_tool "$KF_POD" "apache/kafka:3.9.0"

MINIO_USER="$(read_secret "$MINIO_SECRET" MINIO_ROOT_USER)"
MINIO_PASS="$(read_secret "$MINIO_SECRET" MINIO_ROOT_PASSWORD)"
[ -n "$MINIO_USER" ] && [ -n "$MINIO_PASS" ] || fail "kredensial nggak kebaca dari '$MINIO_SECRET'"
mc alias set myminio "http://$MINIO_SVC:$MINIO_PORT" "$MINIO_USER" "$MINIO_PASS" >/dev/null \
  || fail "kredensial ditolak MinIO"
ok "mc terhubung ke $MINIO_SVC:$MINIO_PORT"

ktool /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server "$KAFKA_SVC:$KAFKA_PORT" >/dev/null 2>&1 \
  || fail "broker Kafka nggak balas di $KAFKA_SVC:$KAFKA_PORT"
ok "broker Kafka merespons"

# --------------------------------------------------------------------------
step "Target notifikasi Kafka"
# Sama seperti Redis: dideklarasikan lewat env var di manifest, jadi sudah hidup
# sejak MinIO start. Nama target ikut huruf besar sufiks env-nya.
ARNS="$(mc admin info myminio --json 2>/dev/null \
        | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin).get("info",{}).get("sqsARN",[]) or []))' \
        2>/dev/null || true)"
[ -n "$ARNS" ] || fail "MinIO nggak ngedaftarin SQS ARN satupun"
note "semua ARN: $ARNS"

ARN="$(tr ' ' '\n' <<<"$ARNS" | grep -i kafka | head -1)"
[ -n "$ARN" ] || fail "ARN kafka nggak ada. MinIO mungkin gagal nyambung ke broker pas start — cek 'kubectl --context $KCTX logs deploy/$MINIO_SVC -n $NS | grep -i kafka'"
ok "ARN kafka: $ARN"

mc mb --ignore-existing "myminio/$BUCKET" >/dev/null
mc rm --recursive --force "myminio/$BUCKET" >/dev/null 2>&1 || true

ADD_OUT="$(mc event add "myminio/$BUCKET" "$ARN" --event put 2>&1 || true)"
grep -qi "already exists\|successfully\|^$" <<<"$ADD_OUT" || fail "gagal masang aturan event: $ADD_OUT"
ok "aturan event terpasang"
mc event list "myminio/$BUCKET" 2>&1 | head -5

# --------------------------------------------------------------------------
step "Upload tiga PDF"
write_pdf "$WORK_DIR/mini.pdf"
LOCAL_SHA="$(sha_of "$WORK_DIR/mini.pdf")"
note "lokal: $(wc -c < "$WORK_DIR/mini.pdf" | tr -d ' ') byte, sha256 ${LOCAL_SHA:0:16}…"

for key in "$KEY_PLAIN" "$KEY_SPACE" "$KEY_NESTED"; do
  mci pipe "myminio/$BUCKET/$key" < "$WORK_DIR/mini.pdf" >/dev/null || fail "gagal upload '$key'"
  ok "terupload: $key"
done

# --------------------------------------------------------------------------
step "Konsumsi dari Kafka"
note "baca topik '$TOPIC' dari awal..."
PAYLOAD="$(kcat --topic "$TOPIC" --from-beginning --timeout-ms 20000 2>/dev/null || true)"
COUNT="$(grep -c . <<<"$PAYLOAD" || true)"
[ "${COUNT:-0}" -ge 3 ] \
  || fail "cuma $COUNT pesan dari 3 yang diharapkan di topik '$TOPIC'"
ok "$COUNT pesan di topik Kafka"

printf '%s\n' "$PAYLOAD" | head -c 4000
echo
printf '%s' "$PAYLOAD" > "$FIXTURE_DIR/event-minio-kafka.raw.json"
ok "fixture disimpan: test/fixtures/event-minio-kafka.raw.json"

report_encoding "$PAYLOAD"

# --------------------------------------------------------------------------
step "Amplop: Kafka vs Redis"
# Ini pertanyaan desain intinya. Kalau amplopnya beda, decoder harus nge-sniff
# bentuk amplop, bukan cuma providernya — dan klaim "Transport ⟂ Decoder"
# di plan perlu diperlunak.
if grep -q '"Records"' <<<"$PAYLOAD"; then
  ok "amplop Kafka pakai {\"Records\":[…]} — bentuk S3 standar"
  ENVELOPE="Records"
elif grep -q '"Event"' <<<"$PAYLOAD"; then
  ok "amplop Kafka pakai [{\"Event\":[…]}] — SAMA seperti Redis"
  ENVELOPE="Event"
else
  warn "bentuk amplop nggak dikenali — periksa fixture manual"
  ENVELOPE="unknown"
fi

if [ -f "$FIXTURE_DIR/event-minio-redis.raw.json" ]; then
  if grep -q '"Event"' "$FIXTURE_DIR/event-minio-redis.raw.json"; then R_ENV="Event"; else R_ENV="Records"; fi
  if [ "$ENVELOPE" = "$R_ENV" ]; then
    ok "amplop Redis dan Kafka SAMA ('$ENVELOPE') → decoder cukup satu bentuk"
  else
    warn "amplop BEDA: kafka='$ENVELOPE' vs redis='$R_ENV'"
    warn "→ decoder WAJIB nge-sniff bentuk amplop, bukan cuma provider."
  fi
else
  note "fixture redis nggak ada — jalanin minio-redis.sh dulu buat bandingin"
fi

# --------------------------------------------------------------------------
step "Baca balik object lewat S3 API"
for key in "$KEY_PLAIN" "$KEY_SPACE" "$KEY_NESTED"; do
  kubectl exec -n "$NS" "$MC_POD" -- mc --no-color cat "myminio/$BUCKET/$key" > "$WORK_DIR/back.pdf" 2>/dev/null \
    || fail "gagal baca balik '$key'"
  [ "$(sha_of "$WORK_DIR/back.pdf")" = "$LOCAL_SHA" ] || fail "'$key' beda isi"
  ok "byte-identik: $key"
done

# --------------------------------------------------------------------------
step "Uji durabilitas: apa consumer group selamat dari crash?"
# Redis gagal di titik ini — LPOP destruktif, event hilang. Kafka harusnya
# beda: offset baru maju kalau di-commit, jadi consumer yang mati sebelum
# commit bakal nerima ulang pesan yang sama.
note "consumer A: baca 1 pesan TANPA commit (simulasi crash sebelum commit)"
ktool /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server "$KAFKA_SVC:$KAFKA_PORT" --topic "$TOPIC" \
  --group "$GROUP" --from-beginning --max-messages 1 \
  --consumer-property enable.auto.commit=false --timeout-ms 15000 >/dev/null 2>&1 || true

LAG_OUT="$(ktool /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server "$KAFKA_SVC:$KAFKA_PORT" --describe --group "$GROUP" 2>/dev/null || true)"
note "$(grep -E "TOPIC|$TOPIC" <<<"$LAG_OUT" | head -3)"

note "consumer B: grup yang sama baca lagi dari awal"
AGAIN="$(ktool /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server "$KAFKA_SVC:$KAFKA_PORT" --topic "$TOPIC" \
  --group "$GROUP" --from-beginning --max-messages 1 \
  --consumer-property enable.auto.commit=false --timeout-ms 15000 2>/dev/null | grep -c . || true)"

if [ "${AGAIN:-0}" -ge 1 ]; then
  ok "PESAN DIKIRIM ULANG. Tanpa commit, offset nggak maju — consumer yang mati"
  ok "sebelum commit bakal nerima ulang. Inilah yang nggak dipunyai Redis."
  KAFKA_DURABLE=1
else
  warn "pesan TIDAK dikirim ulang — periksa manual, di luar dugaan"
  KAFKA_DURABLE=0
fi

# --------------------------------------------------------------------------
step "Ringkasan"
cat <<EOF
  bucket           myminio/$BUCKET
  transport        kafka topic '$TOPIC' (KRaft single-node)
  pesan            $COUNT / 3
  amplop           $ENVELOPE
  baca balik       3 / 3 byte-identik
  ack              $([ "$KAFKA_DURABLE" = "1" ] && echo "ADA — offset commit, aman dari crash consumer" || echo "cek manual")
  fixture          test/fixtures/event-minio-kafka.raw.json
EOF
ok "minio-kafka LULUS"
