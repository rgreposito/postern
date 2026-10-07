#!/bin/sh
# smoke the happy path against a local posternd.
# run from repo root: ./examples/connect.sh
set -eu
URL="${POSTERN_URL:-http://127.0.0.1:8443}"

echo "== health"
curl -sf "$URL/healthz"
echo

echo "== workload grant"
curl -sf -X POST "$URL/v1/grants" \
  -H 'content-type: application/json' \
  -d '{
    "kind":"workload",
    "principal":"spiffe://prod/ns/payments/sa/ledger",
    "action":"connect",
    "resource":"tcp://ledger-db.prod.internal:5432",
    "ttl":"5m",
    "attrs":{"network":"10.8.12.4"}
  }' | python3 -m json.tool | head -n 20
