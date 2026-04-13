#!/usr/bin/env bash
set -euo pipefail
BASE=http://localhost:18080

echo "[*] Health still works"
curl -s $BASE/health | jq .

echo
echo "[*] Legitimate proxy-health still works"
curl -s $BASE/proxy-health | jq .

echo
echo "[*] Userinfo SSRF should now be blocked"
STATUS=$(curl -s -o /tmp/cmiyc1.json -w '%{http_code}' "$BASE/fetch?url=http://gateway@internal-admin-a:5001/debug/config")
echo "status=$STATUS"
cat /tmp/cmiyc1.json | jq .

echo
echo "[*] Redirect SSRF to token discovery should now be blocked"
STATUS=$(curl -s -o /tmp/cmiyc2.json -w '%{http_code}' "$BASE/fetch?url=http://redirector:5002/to-token-discovery")
echo "status=$STATUS"
cat /tmp/cmiyc2.json | jq .

echo
echo "[*] Raw token helper should be retired or locked down"
STATUS=$(curl -s -o /tmp/cmiyc3.json -w '%{http_code}' "$BASE/ops/raw-token")
echo "status=$STATUS"
cat /tmp/cmiyc3.json | jq . || true
