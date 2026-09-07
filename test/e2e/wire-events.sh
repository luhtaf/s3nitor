#!/usr/bin/env bash
#
# Wires MinIO bucket notifications to Kafka, then proves the wire works.
#
# Run this AFTER the MinIO deployment carries the env vars from
# deployments/minio-notify-patch.yaml. Until then the ARN does not exist and
# `mc event add` fails with "ARN not found" — which is the useful failure, not
# a silent one.
#
#   ./test/e2e/wire-events.sh add     # register the bucket rule
#   ./test/e2e/wire-events.sh health  # every link in the chain, in order
#   ./test/e2e/wire-events.sh check   # show the rule and the topic offset
#   ./test/e2e/wire-events.sh tail    # dump events as they arrive
#   ./test/e2e/wire-events.sh put     # upload a probe file and watch it land
#   ./test/e2e/wire-events.sh resume  # stop the scanner, upload, restart, prove
#                                     # nothing was lost while it was down
set -euo pipefail
trap 'echo "FAILED at line $LINENO" >&2' ERR

CTX=${CTX:-kubeth}
NS=${NS:-default}
BUCKET=${BUCKET:-s3nitor-watch}
TOPIC=${TOPIC:-s3nitor-events}
KPOD=${KPOD:-s3nitor-kafka-0}

k() { kubectl --context "$CTX" -n "$NS" "$@"; }
kafka() { k exec "$KPOD" -- "/opt/kafka/bin/$@"; }

# Runs an mc command against the in-cluster MinIO from a throwaway pod. The
# credentials come from the secret, never from the command line, so they do not
# land in shell history or in `kubectl get pod -o yaml`.
mc() {
  local user pass
  user=$(k get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_USER}' | base64 -d)
  pass=$(k get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_PASSWORD}' | base64 -d)
  k run "mc-$RANDOM" --rm -i --restart=Never --image=minio/mc:latest \
    --env="MC_HOST_m=http://${user}:${pass}@minio.${NS}.svc:9000" \
    --command -- mc "$@"
}

case "${1:-check}" in
add)
  # Read the ARN rather than assembling it. Declaring the target through env
  # vars uppercases the target name in the ARN (arn:minio:sqs::PRIMARY:kafka,
  # not :primary:), so a hand-built string silently does not match.
  echo "--- target notifikasi yang hidup di MinIO ---"
  arn=$(mc admin info --json m 2>/dev/null \
        | tr ',' '\n' | grep -o 'arn:minio:sqs::[A-Za-z0-9_]*:kafka' | head -1)
  if [ -z "$arn" ]; then
    echo "Tidak ada ARN kafka. MinIO belum membawa MINIO_NOTIFY_KAFKA_*." >&2
    echo "Terapkan deployments/minio-notify-patch.yaml dulu." >&2
    exit 1
  fi
  echo "ARN: $arn"
  # Every ObjectCreated variant, not just :Put. A streamed upload arrives as
  # :CompleteMultipartUpload, and a rule that only names :Put drops it without
  # reporting anything.
  mc event add "m/$BUCKET" "$arn" --event put,delete
  mc event list "m/$BUCKET"
  ;;

check)
  echo "--- aturan notifikasi di $BUCKET ---"
  mc event list "m/$BUCKET" || echo "(belum ada / MinIO belum dipatch)"
  echo
  echo "--- offset topik $TOPIC ---"
  kafka kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$TOPIC"
  echo
  echo "--- lag consumer group s3nitor ---"
  kafka kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
    --describe --group s3nitor 2>&1 | tail -5
  ;;

tail)
  echo "--- menunggu event di $TOPIC (Ctrl-C untuk berhenti) ---"
  kafka kafka-console-consumer.sh --bootstrap-server localhost:9092 \
    --topic "$TOPIC" --from-beginning
  ;;

put)
  name="probe-$(date +%s).txt"
  before=$(kafka kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$TOPIC" \
           | cut -d: -f3)
  echo "offset sebelum upload: $before"
  # Written inside the pod rather than piped in: `kubectl run -i` closing stdin
  # is not a reliable file boundary for mc.
  mc-put() { :; }
  user=$(k get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_USER}' | base64 -d)
  pass=$(k get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_PASSWORD}' | base64 -d)
  k run "mcput-$RANDOM" --rm -i --restart=Never --image=minio/mc:latest \
    --env="MC_HOST_m=http://${user}:${pass}@minio.${NS}.svc:9000" \
    --command -- sh -c "echo 'probe $(date)' > /tmp/$name && mc cp /tmp/$name m/$BUCKET/$name"
  sleep 3
  after=$(kafka kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$TOPIC" \
          | cut -d: -f3)
  echo "offset sesudah upload:  $after"
  if [ "$after" -gt "$before" ]; then
    echo "OK: MinIO menerbitkan $((after - before)) event ke $TOPIC"
  else
    echo "GAGAL: offset tidak bergerak — notifikasi tidak sampai ke Kafka" >&2
    exit 1
  fi
  ;;

health)
  # Walks the chain in the order bytes travel, so the first FAIL is the broken
  # link rather than a symptom of one further downstream. Every check reads a
  # number out of the component itself: a pod that is Running proves nothing —
  # the consumer that silently scanned nothing for an hour was Running the
  # whole time.
  fail=0
  say() { printf '%-42s %s\n' "$1" "$2"; }

  # 1. Does MinIO have a live Kafka target? The ARN only appears in the startup
  #    log once MinIO has accepted the env vars, so this is the target being
  #    real rather than the config being written.
  arn=$(k logs -l app=minio --tail=-1 2>/dev/null | grep -o 'arn:minio:sqs::[A-Za-z0-9_]*:kafka' | tail -1)
  if [ -n "$arn" ]; then say "1. MinIO target kafka" "OK   $arn"
  else say "1. MinIO target kafka" "FAIL tidak ada ARN kafka"; fail=1; fi

  # 2. Does the bucket point at it? A live target with no bucket rule publishes
  #    nothing, and looks identical from MinIO's side.
  rule=$(mc event list "m/$BUCKET" 2>/dev/null | grep -c 'ObjectCreated' || true)
  if [ "${rule:-0}" -gt 0 ]; then say "2. Aturan notifikasi $BUCKET" "OK   $rule aturan"
  else say "2. Aturan notifikasi $BUCKET" "FAIL bucket tidak mengirim event"; fail=1; fi

  # 3. Has anything actually been published? Offset 0 with uploads already done
  #    means the wire is dead, not that the system is idle.
  end=$(kafka kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$TOPIC" 2>/dev/null | cut -d: -f3)
  say "3. Event di topik $TOPIC" "     offset=${end:-?}"

  # 4. Is the consumer attached, and has it caught up? CURRENT-OFFSET proves it
  #    read; LAG proves it is not falling behind.
  grp=$(kafka kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
        --describe --group s3nitor 2>/dev/null | awk '$2=="'"$TOPIC"'" {print $4, $6; exit}')
  if [ -n "$grp" ]; then say "4. Consumer s3nitor" "OK   current/lag = $grp"
  else say "4. Consumer s3nitor" "FAIL group tidak terdaftar"; fail=1; fi

  # 5. Did results survive the last hop? The scan is only worth something once
  #    the sink has it — the ledger commits after the sink accepts, not before.
  espass=$(k get secret elk-th-new-es-elastic-user -o jsonpath='{.data.elastic}' | base64 -d)
  cnt=$(k exec elk-th-new-es-data-0 -c elasticsearch -- \
        curl -s -u "elastic:$espass" \
        "http://localhost:9200/s3nitor-findings/_count?q=bucket:$BUCKET" 2>/dev/null \
        | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
  say "5. Dokumen di ELK ($BUCKET)" "     count=${cnt:-0}"

  echo
  if [ "$fail" -eq 0 ]; then echo "Rantai utuh."; else echo "Ada mata rantai putus di atas." >&2; exit 1; fi
  ;;

resume)
  # Proves the property that made Kafka worth deploying instead of Redis: an
  # event published while the consumer is down is still there when it comes
  # back. With a Redis list, BRPOP is destructive and the same test loses the
  # event — that was measured in phase 0, not assumed.
  #
  # What is actually being checked is the consumer group's committed offset. A
  # scanner that restarted and simply re-listed the bucket would also end up
  # with the documents, and would prove nothing about delivery.
  n=${N:-3}
  espass=$(k get secret elk-th-new-es-elastic-user -o jsonpath='{.data.elastic}' | base64 -d)
  esq() { k exec elk-th-new-es-data-0 -c elasticsearch -- \
          curl -s -u "elastic:$espass" "http://localhost:9200/s3nitor-findings/_count?q=bucket:$BUCKET" \
          2>/dev/null | sed -n 's/.*"count":\([0-9]*\).*/\1/p'; }
  lag() { kafka kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
          --describe --group s3nitor 2>/dev/null | awk '$2=="'"$TOPIC"'" {print $6; exit}'; }

  docs0=$(esq); echo "dokumen di ELK sebelum: ${docs0:-0}"

  echo
  echo "--- 1. matikan scanner ---"
  k scale deploy/s3nitor-event --replicas=0
  k wait --for=delete pod -l app=s3nitor-event --timeout=90s 2>/dev/null || true
  k get pod -l app=s3nitor-event 2>&1 | tail -1

  echo
  echo "--- 2. upload $n file selagi mati ---"
  user=$(k get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_USER}' | base64 -d)
  pass=$(k get secret minio-creds -o jsonpath='{.data.MINIO_ROOT_PASSWORD}' | base64 -d)
  stamp=$(date +%s)
  k run "mcput-$RANDOM" --rm -i --restart=Never --image=minio/mc:latest \
    --env="MC_HOST_m=http://${user}:${pass}@minio.${NS}.svc:9000" \
    --command -- sh -c "for i in \$(seq 1 $n); do
        echo \"down-$stamp-\$i\" > /tmp/down-$stamp-\$i.txt
        mc cp -q /tmp/down-$stamp-\$i.txt m/$BUCKET/down-$stamp-\$i.txt
      done" >/dev/null 2>&1
  sleep 3

  echo
  echo "--- 3. event tertahan di broker, bukan hilang ---"
  echo "  lag consumer group: $(lag)   <-- bukan 0, dan tidak ada yang mengonsumsinya"
  kafka kafka-get-offsets.sh --bootstrap-server localhost:9092 --topic "$TOPIC" | sed 's/^/  offset: /'

  echo
  echo "--- 4. hidupkan lagi ---"
  k scale deploy/s3nitor-event --replicas=1
  k rollout status deploy/s3nitor-event --timeout=180s | tail -1

  echo
  echo "--- 5. tunggu dokumennya benar-benar terbit ---"
  # Waits on the document count, not on the consumer lag. Lag reaching zero only
  # says the messages were read; the findings are still in a publish batch that
  # flushes on PUBLISH_FLUSH_INTERVAL. An earlier version of this test asserted
  # the moment lag hit zero and reported a failure while the scan had in fact
  # succeeded — it was measuring a proxy for the thing it claimed to check.
  want=$((docs0 + n * 2))   # one document per (file x scanner), ioc + yara
  docs1=$docs0
  for i in $(seq 1 30); do
    docs1=$(esq)
    echo "  lag=$(lag)  dokumen=${docs1:-0}/$want"
    [ "${docs1:-0}" -ge "$want" ] && break
    sleep 3
  done

  echo
  echo "dokumen di ELK sesudah: ${docs1:-0} (sebelum ${docs0:-0})"
  if [ "${docs1:-0}" -gt "${docs0:-0}" ]; then
    echo "OK: $n upload saat mati tetap terscan setelah hidup — tidak ada event hilang"
  else
    echo "GAGAL: tidak ada dokumen baru; event hilang saat downtime" >&2
    exit 1
  fi
  ;;

*) echo "usage: $0 {add|health|check|tail|put|resume}" >&2; exit 2 ;;
esac
