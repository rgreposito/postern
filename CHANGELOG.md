# Changelog

## 0.1.0 — 2026-04-11

First cut that is not just a folder of notes.

- Policy YAML v1, first-match evaluator, glob matcher
- Human / workload / agent principals
- Short-lived client certs + HMAC tickets
- In-memory sessions with TTL jitter
- HTTP API: `/v1/grants`, `/v1/tickets/verify`, revoke, list
- `posternctl`
- Example policies, helm/k8s/terraform sketches
- ADRs for the three decisions I kept walking back on

Not in this tag: persistence, OIDC, the data-plane proxy.
