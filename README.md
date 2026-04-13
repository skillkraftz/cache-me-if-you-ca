# Cache Me If You CA

Cache Me If You CA is an intentionally vulnerable local Docker Compose lab for iterative security remediation work.

This lab pushes beyond the original SSRF Ring Dojo by adding Redis-backed security state, two internal admin replicas, and a few intentionally bad trust assumptions around token issuance, replay handling, and helper endpoints.

## Services

- gateway: externally exposed SSRF surface and convenience admin helpers
- internal-admin-a / internal-admin-b: two replicas of the privileged admin service
- token-service: internal token minting service with weak client policy and Redis fail-open behavior
- redis: shared state backend used for mint nonces and rate limiting only
- redirector: internal redirector used to test redirect-based SSRF validation

## Baseline behavior

- Some security tests are expected to fail before patching.
- Functional tests should continue to pass after a correct remediation.
- The vulnerable baseline intentionally allows a replay of the same export token against both admin replicas.

## Quick start

```bash
docker compose up -d --build
./scripts/smoke_pre_patch.sh
```

## Verification

```bash
docker compose exec gateway pytest -q
./scripts/smoke_post_patch.sh
```

## Notes

This repository is intentionally insecure. Do not deploy it anywhere except an isolated local lab.
