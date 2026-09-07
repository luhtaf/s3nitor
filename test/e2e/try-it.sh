#!/usr/bin/env bash
#
# Point the scanner at the cluster's MinIO and send findings to elk.th.
#
# Nothing is uploaded for you: the idea is that you drop files into the bucket
# yourself and watch what comes out. Run this once to set up, then again after
# each upload.
#
#   ./test/e2e/try-it.sh setup    # port-forwards, credentials, bucket, index
#   ./test/e2e/try-it.sh scan     # scan whatever is in the bucket now
#   ./test/e2e/try-it.sh show     # what landed in Elasticsearch
#   ./test/e2e/try-it.sh stop     # close the port-forwards
#
# Lister mode, not events: there is no Kafka in this cluster, and for scanning
# a bucket on demand a broker adds nothing.

set -euo pipefail

KCTX="${KCTX:-kubeth}"
NS="${NS:-default}"
BUCKET="${BUCKET:-s3nitor-try}"
ES_INDEX="${ES_INDEX:-s3nitor-findings}"

MINIO_SVC=minio
ES_SVC=elk-th-new-es-http
MINIO_PORT=19000
ES_PORT=19200

STATE="${TMPDIR:-/tmp}/s3nitor-try"
mkdir -p "$STATE"

if [ -t 1 ]; then
  C_H=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_ERR=$'\033[0;31m'
  C_W=$'\033[0;33m'; C_D=$'\033[0;90m'; C_OFF=$'\033[0m'
else C_H=""; C_OK=""; C_ERR=""; C_W=""; C_D=""; C_OFF=""; fi
step(){ printf '\n%s=== %s ===%s\n' "$C_H" "$*" "$C_OFF"; }
ok(){ printf '%s  ok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
warn(){ printf '%s  warn%s %s\n' "$C_W" "$C_OFF" "$*"; }
note(){ printf '%s       %s%s\n' "$C_D" "$*" "$C_OFF"; }
die(){ printf '%s  FAIL%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

k(){ kubectl --context "$KCTX" -n "$NS" "$@"; }

# S3 operations go through the aws CLI against the port-forward.
#
# mc in a container was the obvious choice and the wrong one: the port-forward
# listens on the host, and reaching it from a container needs either host
# networking (unavailable on Docker Desktop, where containers live in a VM) or a
# host-gateway alias — and either way it needs a running Docker daemon for what
# is fundamentally a couple of HTTP requests.
s3(){
  AWS_ACCESS_KEY_ID="$(cat "$STATE/minio_user")" \
  AWS_SECRET_ACCESS_KEY="$(cat "$STATE/minio_pass")" \
  AWS_DEFAULT_REGION=us-east-1 \
  aws --endpoint-url "http://127.0.0.1:$MINIO_PORT" "$@"
}

secret(){ k get secret "$1" -o "jsonpath={.data.$2}" 2>/dev/null | base64 -d; }

forward(){  # forward <svc> <local> <remote> <pidfile>
  if [ -f "$4" ] && kill -0 "$(cat "$4")" 2>/dev/null; then return; fi
  kubectl --context "$KCTX" -n "$NS" port-forward "svc/$1" "$2:$3" >/dev/null 2>&1 &
  echo $! > "$4"
  sleep 3
}

case "${1:-setup}" in

setup)
  step "Kredensial"
  k get svc "$MINIO_SVC" >/dev/null 2>&1 || die "svc/$MINIO_SVC tidak ada di ns $NS"
  k get svc "$ES_SVC"    >/dev/null 2>&1 || die "svc/$ES_SVC tidak ada di ns $NS"

  secret minio-creds MINIO_ROOT_USER     > "$STATE/minio_user"
  secret minio-creds MINIO_ROOT_PASSWORD > "$STATE/minio_pass"
  # ECK stores the superuser password under the username as the key.
  secret elk-th-new-es-elastic-user elastic > "$STATE/es_pass"
  echo elastic > "$STATE/es_user"
  [ -s "$STATE/minio_user" ] || die "kredensial MinIO tidak terbaca"
  [ -s "$STATE/es_pass" ]    || die "kredensial Elasticsearch tidak terbaca"
  # Only the CA is written to disk; the passwords stay in this directory and are
  # never echoed.
  ok "kredensial diambil ke $STATE"

  step "Port-forward"
  forward "$MINIO_SVC" "$MINIO_PORT" 9000 "$STATE/minio.pid"
  forward "$ES_SVC"    "$ES_PORT"    9200 "$STATE/es.pid"
  curl -fsS --max-time 5 "http://127.0.0.1:$MINIO_PORT/minio/health/ready" >/dev/null \
    && ok "MinIO  → 127.0.0.1:$MINIO_PORT" || die "MinIO tidak merespons"
  ES_SCHEME=""
  for scheme in http https; do
    code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
      -u "elastic:$(cat "$STATE/es_pass")" "$scheme://127.0.0.1:$ES_PORT" || true)
    if [ "$code" = "200" ]; then ES_SCHEME="$scheme"; break; fi
    if [ "$code" = "401" ]; then ES_SCHEME="$scheme"; warn "$scheme merespons 401 — kredensial ditolak"; break; fi
  done
  [ -n "$ES_SCHEME" ] || die "Elasticsearch tidak merespons di http maupun https"
  echo "$ES_SCHEME" > "$STATE/es_scheme"
  ok "Elasticsearch → $ES_SCHEME://127.0.0.1:$ES_PORT"

  # Only fetch the CA when the cluster actually serves TLS.
  if [ "$ES_SCHEME" = "https" ]; then
    k get secret elk-th-new-es-http-certs-public -o "jsonpath={.data.ca\.crt}" 2>/dev/null \
      | base64 -d > "$STATE/es-ca.crt" || true
    [ -s "$STATE/es-ca.crt" ] && ok "CA Elasticsearch tersimpan" \
      || warn "CA tidak terbaca — pakai ES_INSECURE_SKIP_VERIFY=true"
  else
    rm -f "$STATE/es-ca.crt"
    note "TLS dimatikan di cluster ini, jadi tidak ada CA yang perlu diambil"
  fi

  step "Bucket"
  command -v aws >/dev/null || die "aws CLI tidak ada — 'brew install awscli'"
  if s3 s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
    ok "bucket '$BUCKET' sudah ada"
  elif out=$(s3 s3 mb "s3://$BUCKET" 2>&1); then
    ok "bucket '$BUCKET' dibuat"
  else
    echo "$out" | tail -2 | sed 's/^/    /'
    die "gagal membuat bucket '$BUCKET'"
  fi
  note "isi sekarang: $(s3 s3 ls "s3://$BUCKET" --recursive 2>/dev/null | wc -l | tr -d ' ') objek"

  cat <<EOF

  Sekarang giliranmu. Unggah apa saja ke bucket '$BUCKET':

    ${C_H}Console MinIO${C_OFF}
      kubectl --context $KCTX -n $NS port-forward svc/$MINIO_SVC 19001:9001
      buka http://127.0.0.1:19001  (user: $(cat "$STATE/minio_user"))

    ${C_H}atau lewat skrip ini${C_OFF}
      ./test/e2e/try-it.sh put berkasmu.pdf
      ./test/e2e/try-it.sh put *.pdf

  Lalu:  ./test/e2e/try-it.sh scan
EOF
  ;;

scan)
  [ -s "$STATE/es_pass" ] || die "jalankan 'setup' dulu"
  forward "$MINIO_SVC" "$MINIO_PORT" 9000 "$STATE/minio.pid"
  forward "$ES_SVC"    "$ES_PORT"    9200 "$STATE/es.pid"

  step "Build"
  CGO_ENABLED=1 go build -o "$STATE/s3scanner" ./cmd/s3scanner || die "build gagal"

  step "Scan"
  # A per-run database, so re-running always rescans. Drop these lines to keep
  # dedup between runs.
  #
  # The -wal and -shm sidecars go too: removing only the main file leaves SQLite
  # to open a fresh database beside a stale write-ahead log, which fails as
  # "disk I/O error" rather than as anything that names the cause.
  rm -f "$STATE/try.db" "$STATE/try.db-wal" "$STATE/try.db-shm"
  ES_SCHEME="$(cat "$STATE/es_scheme" 2>/dev/null || echo http)"
  # An empty ES_CA_CERT already means "no custom CA", so there is no need for a
  # conditional array — which bash 3.2, still the default on macOS, refuses to
  # expand when empty under `set -u`.
  ES_CA=""
  [ -s "$STATE/es-ca.crt" ] && ES_CA="$STATE/es-ca.crt"

  env \
    DB_DRIVER=sqlite3 DB_DSN="$STATE/try.db" \
    S3_ENDPOINT="http://127.0.0.1:$MINIO_PORT" S3_BUCKET="$BUCKET" \
    S3_ACCESS_KEY="$(cat "$STATE/minio_user")" S3_SECRET_KEY="$(cat "$STATE/minio_pass")" \
    AWS_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true \
    SOURCE_MODE=lister \
    ENABLE_IOC=true ENABLE_YARA=true ENABLE_OTX=false ENABLE_VT=false \
    REPORTER_TYPE=elasticsearch \
    ES_URL="$ES_SCHEME://127.0.0.1:$ES_PORT" ES_INDEX="$ES_INDEX" \
    ES_USERNAME=elastic ES_PASSWORD="$(cat "$STATE/es_pass")" \
    ES_CA_CERT="$ES_CA" \
    METRICS_ADDR=:19090 \
    "$STATE/s3scanner"

  echo
  note "temuan dikirim ke index '$ES_INDEX'"
  note "lihat dengan: ./test/e2e/try-it.sh show"
  ;;

put)
  shift
  [ $# -gt 0 ] || die "pakai: ./test/e2e/try-it.sh put <berkas> [berkas...]"
  [ -s "$STATE/minio_user" ] || die "jalankan 'setup' dulu"
  forward "$MINIO_SVC" "$MINIO_PORT" 9000 "$STATE/minio.pid"

  step "Unggah"
  for f in "$@"; do
    [ -f "$f" ] || { warn "lewati $f — bukan berkas"; continue; }
    if s3 s3 cp "$f" "s3://$BUCKET/$(basename "$f")" >/dev/null 2>&1; then
      ok "$(basename "$f")  ($(wc -c < "$f" | tr -d ' ') byte)"
    else
      warn "gagal mengunggah $f"
    fi
  done
  note "lalu: ./test/e2e/try-it.sh scan"
  ;;

ls)
  [ -s "$STATE/minio_user" ] || die "jalankan 'setup' dulu"
  forward "$MINIO_SVC" "$MINIO_PORT" 9000 "$STATE/minio.pid"
  step "Isi bucket '$BUCKET'"
  s3 s3 ls "s3://$BUCKET" --recursive --human-readable || true
  ;;

show)
  [ -s "$STATE/es_pass" ] || die "jalankan 'setup' dulu"
  forward "$ES_SVC" "$ES_PORT" 9200 "$STATE/es.pid"

  step "Temuan di index '$ES_INDEX'"
  ES_SCHEME="$(cat "$STATE/es_scheme" 2>/dev/null || echo http)"
  curl -fsSk -u "elastic:$(cat "$STATE/es_pass")" \
    "$ES_SCHEME://127.0.0.1:$ES_PORT/$ES_INDEX/_search?size=50&sort=scanned_at:desc" \
    | python3 -c "
import json,sys
r = json.load(sys.stdin)
hits = r.get('hits',{}).get('hits',[])
if not hits:
    print('  (kosong — sudah menjalankan scan?)'); sys.exit()
total = r['hits']['total']['value']
print(f'  {total} dokumen\n')
print(f\"  {'KEY':<38} {'SCANNER':<12} {'MATCH':<6} {'SEVERITY':<9} DETAIL\")
print('  ' + '-'*96)
for h in hits:
    d = h['_source']
    det = json.dumps(d.get('detail',{}))[:34]
    print(f\"  {d['key'][:37]:<38} {d['scanner']:<12} {str(d['match']):<6} {d['severity']:<9} {det}\")
"
  echo
  note "Kibana: kubectl --context $KCTX -n $NS port-forward svc/elk-th-new-kb-http 5601:5601"
  note "lalu buka https://127.0.0.1:5601 dan bikin data view '$ES_INDEX*'"
  ;;

stop)
  for f in "$STATE"/*.pid; do
    [ -e "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  done
  ok "port-forward ditutup"
  ;;

*) die "pakai: setup | put <berkas> | ls | scan | show | stop" ;;
esac
