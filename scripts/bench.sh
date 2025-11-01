#!/usr/bin/env bash
set -euo pipefail

if ! command -v vegeta &>/dev/null && ! command -v hey &>/dev/null; then
  echo "Install vegeta or hey to run the micro-bench." >&2
  exit 1
fi

TARGET_URL=${TARGET_URL:-https://localhost/guard}
DURATION=${DURATION:-30s}
RATE=${RATE:-10}

if command -v vegeta &>/dev/null; then
  echo "POST ${TARGET_URL}" | vegeta attack -duration=${DURATION} -rate=${RATE} | vegeta report
elif command -v hey &>/dev/null; then
  hey -z ${DURATION} -c ${RATE} -m POST -d '{"response": "test", "policy_id": "default"}' ${TARGET_URL}
fi
