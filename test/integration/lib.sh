#!/usr/bin/env bash
# Helper bersama untuk skrip integrasi Fase 0.
#
# Prinsipnya: semua tooling (mc, redis-cli, kafka client) dijalanin sebagai pod
# di dalam cluster, bukan diinstal ke laptop. Pod bisa manggil service lewat DNS
# internal, jadi nggak perlu port-forward sama sekali.

set -euo pipefail

# Context dinyatakan eksplisit, bukan ngandelin current-context. Skrip ini bikin
# dan ngehapus resource — nyasar ke cluster lain gara-gara context kegeser itu
# mahal. Semua panggilan lewat wrapper kubectl() di bawah.
KCTX="${KCTX:-kubeth}"
NS="${NS:-default}"
BUCKET="${BUCKET:-s3nitor-test}"

kubectl() { command kubectl --context "$KCTX" "$@"; }

# PDF minimal 593 byte, valid (PDF 1.4, 1 halaman). Ditaruh base64 supaya
# nggak ada binary yang ke-commit ke repo.
PDF_B64="JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2UgL1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCAyMDAgMTAwXSAvQ29udGVudHMgNCAwIFIgL1Jlc291cmNlcyA8PCAvRm9udCA8PCAvRjEgNSAwIFIgPj4gPj4gPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCA0OSA+PgpzdHJlYW0KQlQgL0YxIDEyIFRmIDIwIDUwIFRkIChzM25pdG9yIHBoYXNlMCB0ZXN0KSBUaiBFVAplbmRzdHJlYW0KZW5kb2JqCjUgMCBvYmoKPDwgL1R5cGUgL0ZvbnQgL1N1YnR5cGUgL1R5cGUxIC9CYXNlRm9udCAvSGVsdmV0aWNhID4+CmVuZG9iagp4cmVmCjAgNgowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMDkgMDAwMDAgbiAKMDAwMDAwMDA1OCAwMDAwMCBuIAowMDAwMDAwMTE1IDAwMDAwIG4gCjAwMDAwMDAyNDEgMDAwMDAgbiAKMDAwMDAwMDM0MCAwMDAwMCBuIAp0cmFpbGVyCjw8IC9TaXplIDYgL1Jvb3QgMSAwIFIgPj4Kc3RhcnR4cmVmCjQxMAolJUVPRgo="

# Tiga key yang sengaja dipilih untuk menjawab pertanyaan spesifik di plan:
#   plain            — kasus normal, baseline
#   "with space"     — buktiin key di-URL-encode atau nggak di payload event
#   nested/deep/path — buktiin key ber-prefix keluar utuh, bukan cuma basename
KEY_PLAIN="plain.pdf"
KEY_SPACE="with space.pdf"
KEY_NESTED="nested/deep/path.pdf"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_DIR="$REPO_ROOT/test/fixtures"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ---- output ----------------------------------------------------------------

if [ -t 1 ]; then
  C_HEAD=$'\033[1;36m'; C_OK=$'\033[0;32m'; C_WARN=$'\033[0;33m'
  C_ERR=$'\033[0;31m';  C_DIM=$'\033[0;90m'; C_OFF=$'\033[0m'
else
  C_HEAD=""; C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi

# `set -e` + `pipefail` bikin perintah gagal ngebunuh skrip TANPA pesan apapun.
# Jebakan ini ngasih tau baris dan perintah mana yang jatuh, supaya kegagalan
# nggak pernah senyap.
trap 'rc=$?; if [ "$rc" -ne 0 ]; then
        printf "\n%s  ABORT%s baris %s: %s (exit %s)\n" \
          "${C_ERR:-}" "${C_OFF:-}" "${BASH_LINENO[0]}" "${BASH_COMMAND}" "$rc" >&2
      fi' ERR

step() { printf '\n%s=== %s ===%s\n' "$C_HEAD" "$*" "$C_OFF"; }
ok()   { printf '%s  ok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s  warn%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
fail() { printf '%s  FAIL%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }
note() { printf '%s       %s%s\n' "$C_DIM" "$*" "$C_OFF"; }

# ---- pod toolbox -----------------------------------------------------------

# spawn_tool <nama-pod> <image> — bikin pod idle yang bisa di-exec berkali-kali.
# Sekali-jalan `kubectl run --rm` nggak cukup karena tiap langkah butuh state
# (alias mc, misalnya) dan kita perlu banyak perintah berurutan.
spawn_tool() {
  local pod="$1" image="$2"
  kubectl delete pod "$pod" -n "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl run "$pod" -n "$NS" --image="$image" --restart=Never \
    --command -- sleep 3600 >/dev/null
  kubectl wait --for=condition=Ready "pod/$pod" -n "$NS" --timeout=120s >/dev/null \
    || fail "pod $pod ($image) nggak pernah Ready"
  ok "pod $pod siap ($image)"
}

cleanup_tools() {
  for pod in "$@"; do
    kubectl delete pod "$pod" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}

require_svc() {
  kubectl get svc "$1" -n "$NS" >/dev/null 2>&1 \
    || fail "service '$1' nggak ada di namespace '$NS'. Setel NS= atau deploy dulu."
}

# ---- stack uji sekali-pakai ------------------------------------------------

# Deploy MinIO + Redis khusus tes. Instance sendiri, bukan yang bersama, karena
# ngaktifin config notifikasi butuh restart MinIO — dan MinIO bersama dipakai ELK.
ensure_test_stack() {
  local manifest="$REPO_ROOT/test/integration/manifests/test-stack.yaml"

  # Kredensial diacak tiap kali stack dibikin, bukan ditulis di manifest.
  if ! kubectl get secret s3nitor-test-minio-creds -n "$NS" >/dev/null 2>&1; then
    local u p
    # Pakai `od -N` yang baca jumlah byte tetap. Jangan `tr </dev/urandom | head -c`:
    # head nutup pipe, tr kena SIGPIPE, dan dengan `set -o pipefail` seluruh skrip
    # mati tanpa pesan apa-apa.
    u="s3nitortest$(od -An -tx1 -N4 /dev/urandom | tr -d ' \n')"
    p="$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"
    kubectl create secret generic s3nitor-test-minio-creds -n "$NS" \
      --from-literal=MINIO_ROOT_USER="$u" \
      --from-literal=MINIO_ROOT_PASSWORD="$p" >/dev/null
    kubectl label secret s3nitor-test-minio-creds -n "$NS" \
      app.kubernetes.io/part-of=s3nitor-test --overwrite >/dev/null
    ok "kredensial uji dibuat acak (secret s3nitor-test-minio-creds)"
  else
    note "pakai secret uji yang sudah ada"
  fi

  kubectl apply -f "$manifest" -n "$NS" >/dev/null

  # Kafka duluan: MinIO nyoba nyambung ke target notifikasi pas start. queue_dir
  # sudah nutup kasus Kafka telat, tapi nunggu di sini bikin hasilnya nggak
  # bergantung pada balapan startup.
  kubectl rollout status deployment/s3nitor-test-kafka -n "$NS" --timeout=240s >/dev/null \
    || fail "Kafka uji nggak pernah siap — cek 'kubectl --context $KCTX logs deploy/s3nitor-test-kafka -n $NS'"
  kubectl rollout status deployment/s3nitor-test-redis -n "$NS" --timeout=120s >/dev/null \
    || fail "Redis uji nggak pernah siap"
  kubectl rollout status deployment/s3nitor-test-minio -n "$NS" --timeout=180s >/dev/null \
    || fail "MinIO uji nggak pernah siap"
  ok "stack uji siap (minio, redis, kafka)"
}

# Restart MinIO uji — aman, karena instance ini cuma dipakai skrip tes.
restart_test_minio() {
  kubectl rollout restart deployment/s3nitor-test-minio -n "$NS" >/dev/null
  kubectl rollout status deployment/s3nitor-test-minio -n "$NS" --timeout=180s >/dev/null \
    || fail "rollout MinIO uji nggak selesai"
}

teardown_test_stack() {
  kubectl delete all,secret -l app.kubernetes.io/part-of=s3nitor-test -n "$NS" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

# ---- pembanding ------------------------------------------------------------

sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# write_pdf <path> — tulis PDF uji ke filesystem lokal.
write_pdf() { printf '%s' "$PDF_B64" | base64 -d > "$1"; }

# Cetak apakah sebuah key muncul dalam bentuk ter-encode di payload.
# Ini yang menjawab pertanyaan "key-nya di-URL-encode atau nggak" — jangan
# ditebak dari dokumentasi, lihat byte-nya langsung.
report_encoding() {
  local payload="$1"
  step "Encoding key di payload"

  # Spasi: bentuknya nentuin fungsi unescape mana yang benar di Go.
  #   %20  → PathUnescape ATAU QueryUnescape dua-duanya benar
  #   +    → HANYA QueryUnescape yang benar; PathUnescape ninggalin '+' apa adanya
  if grep -q 'with+space' <<<"$payload"; then
    ok "spasi jadi '+' → WAJIB url.QueryUnescape (PathUnescape bakal ninggalin '+')"
  elif grep -q 'with%20space' <<<"$payload"; then
    ok "spasi jadi %20 → PathUnescape atau QueryUnescape sama-sama jalan"
  elif grep -q 'with space' <<<"$payload"; then
    warn "spasi mentah, TIDAK di-encode → jangan unescape, nanti malah rusak"
  else
    warn "key berspasi nggak ketemu di payload — cek manual"
  fi

  # Separator path: kalau '/' ikut di-encode jadi %2F, key nggak bisa dipakai
  # langsung sebagai path — harus di-unescape dulu sebelum dipakai ke S3 API.
  if grep -q 'nested%2Fdeep%2Fpath' <<<"$payload"; then
    ok "'/' ikut di-encode jadi %2F → key WAJIB di-unescape sebelum dipakai"
  elif grep -q 'nested/deep/path' <<<"$payload"; then
    ok "'/' dibiarkan mentah, prefix keluar utuh"
  else
    warn "key nested nggak ketemu dalam bentuk apapun — cek manual"
  fi
}
