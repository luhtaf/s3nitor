#!/usr/bin/env bash
#
# Fase 0 — SeaweedFS → Kafka. Nol kode Go.
#
# SeaweedFS itu kasus paling ekstrem di rencana, dan alasan utama kenapa
# EventDecoder dipisah dari Transport:
#
#   - Notifikasi keluar dari lapisan FILER, bukan lapisan S3. Yang dikirim itu
#     event filesystem (path + entry), bukan event S3 (bucket + key).
#   - Wire-nya PROTOBUF (filer_pb.EventNotification), bukan JSON.
#   - Nggak ada ETag ala S3, jadi `Version` harus diambil dari field lain.
#
# Pertanyaan yang dijawab skrip ini:
#   1. Bentuk pesan protobuf-nya kayak apa (nomor field, tipe, isi)
#   2. Gimana path filer memetakan ke bucket + key
#   3. Field mana yang layak dipakai jadi `Version` karena ETag nggak ada
#   4. Apa key-nya di-encode kayak MinIO
#
# Pakai:  ./test/integration/seaweedfs-kafka.sh
# Env:    KCTX (default kubeth), NS, KEEP_STACK=1

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SW_SVC="${SW_SVC:-s3nitor-test-seaweedfs}"
KAFKA_SVC="${KAFKA_SVC:-s3nitor-test-kafka}"
SW_S3_PORT="${SW_S3_PORT:-8333}"
KAFKA_PORT="${KAFKA_PORT:-9092}"
SW_SECRET="s3nitor-test-seaweedfs-creds"
SW_TOPIC="${SW_TOPIC:-seaweedfs_filer}"

MC_POD=s3nitor-mc
KF_POD=s3nitor-kafka-cli
[ "${KEEP_POD:-0}" = "1" ] || trap 'cleanup_tools "$MC_POD" "$KF_POD"; rm -rf "$WORK_DIR"' EXIT

mc()  { kubectl exec -n "$NS" "$MC_POD" -- mc --no-color "$@"; }
mci() { kubectl exec -i -n "$NS" "$MC_POD" -- mc --no-color "$@"; }
ktool() { kubectl exec -n "$NS" "$KF_POD" -- "$@"; }

# Jumlah total pesan di sebuah topik.
#
# Pakai kafka-get-offsets.sh, JANGAN `kafka-run-class.sh kafka.tools.GetOffsetShell`:
# di Kafka 3.9 kelas itu sudah pindah ke org.apache.kafka.tools dan pemanggilan
# lama gagal dengan ClassNotFoundException. Kalau errornya ketelan, offset kebaca
# 0 terus dan skrip ngelaporin "nggak ada event" padahal topiknya penuh.
topic_offset() {
  ktool /opt/kafka/bin/kafka-get-offsets.sh \
    --bootstrap-server "$KAFKA_SVC:$KAFKA_PORT" --topic "$1" 2>/dev/null \
    | awk -F: '{s+=$3} END {print s+0}'
}

read_secret() { kubectl get secret "$1" -n "$NS" -o "jsonpath={.data.$2}" 2>/dev/null | base64 -d; }

# --------------------------------------------------------------------------
step "Preflight"
kubectl version --request-timeout=10s >/dev/null 2>&1 || fail "context '$KCTX' nggak reachable"
ok "context: $KCTX, ns: $NS"
mkdir -p "$FIXTURE_DIR"

# --------------------------------------------------------------------------
step "Stack uji (Kafka dibutuhin SeaweedFS)"
ensure_test_stack
require_svc "$KAFKA_SVC"

# --------------------------------------------------------------------------
step "Deploy SeaweedFS"
# Kredensial S3 diacak dan ditaruh di secret sebagai s3.json utuh — SeaweedFS
# baca file JSON, bukan env var seperti MinIO.
if ! kubectl get secret "$SW_SECRET" -n "$NS" >/dev/null 2>&1; then
  SW_AK="s3nitor$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
  SW_SK="$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"
  cat > "$WORK_DIR/s3.json" <<JSON
{
  "identities": [
    {
      "name": "s3nitor",
      "credentials": [ { "accessKey": "$SW_AK", "secretKey": "$SW_SK" } ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
JSON
  kubectl create secret generic "$SW_SECRET" -n "$NS" \
    --from-file=s3.json="$WORK_DIR/s3.json" \
    --from-literal=accessKey="$SW_AK" \
    --from-literal=secretKey="$SW_SK" >/dev/null
  kubectl label secret "$SW_SECRET" -n "$NS" app.kubernetes.io/part-of=s3nitor-test --overwrite >/dev/null
  ok "kredensial SeaweedFS dibuat acak"
else
  note "pakai secret SeaweedFS yang sudah ada"
fi

kubectl apply -f "$REPO_ROOT/test/integration/manifests/seaweedfs.yaml" -n "$NS" >/dev/null
kubectl rollout status deployment/s3nitor-test-seaweedfs -n "$NS" --timeout=300s >/dev/null \
  || fail "SeaweedFS nggak pernah siap — cek 'kubectl --context $KCTX logs deploy/s3nitor-test-seaweedfs -n $NS'"
ok "SeaweedFS siap (master+volume+filer+s3 satu pod)"

# --------------------------------------------------------------------------
step "Nyiapin pod toolbox"
spawn_tool "$MC_POD" "minio/mc:latest"
spawn_tool "$KF_POD" "apache/kafka:3.9.0"

SW_AK="$(read_secret "$SW_SECRET" accessKey)"
SW_SK="$(read_secret "$SW_SECRET" secretKey)"
mc alias set sw "http://$SW_SVC:$SW_S3_PORT" "$SW_AK" "$SW_SK" >/dev/null \
  || fail "gagal nyambung ke gateway S3 SeaweedFS"
ok "mc terhubung ke gateway S3 SeaweedFS"

# --------------------------------------------------------------------------
step "Bikin bucket dan catat offset Kafka"
mc mb --ignore-existing "sw/$BUCKET" >/dev/null
ok "bucket sw/$BUCKET siap"

# Catat offset akhir SEBELUM upload, supaya cuma event kita yang dibaca —
# bikin bucket sendiri juga nerbitkan event filer.
BASE_OFFSET="$(topic_offset "$SW_TOPIC")"
BASE_OFFSET="${BASE_OFFSET:-0}"
note "offset topik '$SW_TOPIC' sebelum upload: $BASE_OFFSET"

# --------------------------------------------------------------------------
step "Upload tiga PDF"
write_pdf "$WORK_DIR/mini.pdf"
LOCAL_SHA="$(sha_of "$WORK_DIR/mini.pdf")"
for key in "$KEY_PLAIN" "$KEY_SPACE" "$KEY_NESTED"; do
  mci pipe "sw/$BUCKET/$key" < "$WORK_DIR/mini.pdf" >/dev/null || fail "gagal upload '$key'"
  ok "terupload: $key"
done

note "nunggu event filer nyampe Kafka..."
NOW="$BASE_OFFSET"
for i in $(seq 1 20); do
  NOW="$(topic_offset "$SW_TOPIC")"; NOW="${NOW:-0}"
  [ "$NOW" -gt "$BASE_OFFSET" ] && break
  sleep 2
done
NEW=$(( NOW - BASE_OFFSET ))
[ "$NEW" -gt 0 ] || fail "nggak ada event baru di topik '$SW_TOPIC'. Notifikasi filer nggak jalan — cek filer.toml kebaca atau nggak."
ok "$NEW event filer baru"

# --------------------------------------------------------------------------
step "Ambil pesan protobuf mentah"
# Protobuf itu biner: console-consumer bakal ngerusaknya karena nyisipin
# pemisah baris. Ambil satu per satu pakai offset eksplisit, base64-in di dalam
# pod, jadi byte-nya sampai utuh.
: > "$WORK_DIR/messages.b64"
GRABBED=0
for off in $(seq "$BASE_OFFSET" $(( NOW - 1 ))); do
  b64="$(kubectl exec -n "$NS" "$KF_POD" -- sh -c \
    "/opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server $KAFKA_SVC:$KAFKA_PORT \
     --topic $SW_TOPIC --partition 0 --offset $off --max-messages 1 --timeout-ms 10000 2>/dev/null \
     | base64 | tr -d '\n'" 2>/dev/null || true)"
  [ -n "$b64" ] || continue
  printf '%s\n' "$b64" >> "$WORK_DIR/messages.b64"
  GRABBED=$((GRABBED+1))
  # Satu upload S3 nerbitin BEBERAPA event filer (bikin .uploads, tulis part,
  # commit, rename). Batasnya harus muat semuanya buat ketiga key, bukan cuma
  # event pertama — kalau kekecilan, key berspasi dan key nested nggak kelihatan.
  [ "$GRABBED" -ge 24 ] && break
done
[ "$GRABBED" -gt 0 ] || fail "nggak berhasil ngambil satupun pesan mentah"
ok "$GRABBED pesan terambil sebagai base64"
cp "$WORK_DIR/messages.b64" "$FIXTURE_DIR/event-seaweedfs-kafka.b64"
ok "fixture disimpan: test/fixtures/event-seaweedfs-kafka.b64"

# --------------------------------------------------------------------------
step "Struktur protobuf (dibaca tanpa file .proto)"
python3 "$REPO_ROOT/test/integration/protoscan.py" "$WORK_DIR/messages.b64" \
  | tee "$FIXTURE_DIR/event-seaweedfs-kafka.decoded.txt" | head -60
ok "hasil decode disimpan: test/fixtures/event-seaweedfs-kafka.decoded.txt"

# --------------------------------------------------------------------------
step "Path filer → bucket + key"
DECODED="$(cat "$FIXTURE_DIR/event-seaweedfs-kafka.decoded.txt")"
if grep -q '/buckets/' <<<"$DECODED"; then
  ok "path filer diawali /buckets/ → kupas prefix ini buat dapetin bucket+key"
  note "$(grep -o '"/buckets/[^"]*"' <<<"$DECODED" | head -3 | tr '\n' ' ')"
else
  warn "prefix /buckets/ nggak ketemu — lihat string di atas buat tau bentuk path-nya"
fi

step "Encoding key di SeaweedFS"
if grep -q 'with space' <<<"$DECODED"; then
  ok "spasi MENTAH, tidak di-encode → JANGAN unescape (beda dari MinIO!)"
elif grep -q 'with+space\|with%20space' <<<"$DECODED"; then
  warn "key ter-encode — sama seperti MinIO, perlu unescape"
else
  note "key berspasi nggak kebaca sebagai string — cek hasil decode manual"
fi

step "Event .uploads — sampah multipart yang WAJIB disaring"
UPLOADS="$(grep -c '\.uploads' <<<"$DECODED" || true)"
if [ "${UPLOADS:-0}" -gt 0 ]; then
  warn "$UPLOADS event nyangkut di /buckets/<bucket>/.uploads/ — itu potongan"
  warn "multipart yang belum jadi, BUKAN object beneran. Consumer yang nggak"
  warn "nyaring path .uploads bakal nyoba nge-scan file parsial dan bikin"
  warn "hasil palsu. MinIO nggak punya masalah ini karena eventnya di lapisan S3."
else
  ok "nggak ada event .uploads"
fi

step "Kandidat Version dan hash konten"
# Ini nentuin isi ObjectRef.Version buat SeaweedFS.
MTIMES="$(grep -oE '#2 varint = 1[0-9]{9}' <<<"$DECODED" | head -2 | tr '\n' ' ' || true)"
[ -n "$MTIMES" ] && ok "mtime epoch ketemu ($MTIMES) → kandidat utama Version" \
                 || warn "mtime nggak kedeteksi otomatis — cek output decode manual"

if grep -qE '#5 string = "[A-Za-z0-9+/]{22}=="' <<<"$DECODED"; then
  ok "chunk bawa MD5 base64 (16 byte) — SeaweedFS ngasih hash konten,"
  ok "beda dari dugaan awal. Bisa jadi Version yang lebih kuat dari mtime"
  ok "untuk file satu-chunk; file multi-chunk punya MD5 per chunk, bukan per file."
else
  note "field MD5 nggak kedeteksi otomatis — cek output decode manual"
fi
warn "Tetap TIDAK ada ETag ala S3. Version harus diturunkan dari mtime (atau"
warn "MD5 chunk), jadi memisahkan Version dari ETag di ObjectRef terbukti perlu."

# --------------------------------------------------------------------------
step "Baca balik object lewat S3 API"
for key in "$KEY_PLAIN" "$KEY_SPACE" "$KEY_NESTED"; do
  kubectl exec -n "$NS" "$MC_POD" -- mc --no-color cat "sw/$BUCKET/$key" > "$WORK_DIR/back.pdf" 2>/dev/null \
    || fail "gagal baca balik '$key'"
  [ "$(sha_of "$WORK_DIR/back.pdf")" = "$LOCAL_SHA" ] || fail "'$key' beda isi"
  ok "byte-identik: $key"
done

# --------------------------------------------------------------------------
step "Ringkasan"
cat <<EOF
  storage          SeaweedFS 3.80 (master+volume+filer+s3)
  transport        kafka topic '$SW_TOPIC'
  wire             protobuf (filer_pb.EventNotification)
  event baru       $NEW
  pesan terambil   $GRABBED
  baca balik       3 / 3 byte-identik
  fixture          test/fixtures/event-seaweedfs-kafka.b64
                   test/fixtures/event-seaweedfs-kafka.decoded.txt
EOF
ok "seaweedfs-kafka LULUS"
