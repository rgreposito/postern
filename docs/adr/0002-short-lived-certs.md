# ADR 0002 — short-lived certs + HMAC tickets, not JWTs-for-everything

Status: accepted
Date: 2026-03-21

## Context

The data plane has to authorize without a round trip on the hot path.
Two common answers: a signed JWT, or a mutual-TLS identity.

JWTs get copied into logs, browser storage, and Slack. Client certs
do not, but they are annoying to pass through HTTP/1.1 proxies and
anything that is not a TLS listener.

## Decision

Mint both.

- Client cert, P-256, URI SAN = SPIFFE id, TTL capped at 24h in code.
- HMAC-SHA256 ticket over a small claims struct, bound to resource.

The cert is for anything that already speaks TLS (postgres, a future
proxy). The ticket is for HTTP tool gateways (MCP, internal RPCs)
that will not terminate SPIFFE this quarter.

No JWT library. The ticket is two base64 blobs and `crypto/hmac`.
I can read the verifier in one screen, which is the actual requirement.

## Consequences

- Two artifacts to revoke. Revoke the session; both become useless
  once the data plane checks `sid` against the store *or* the ticket
  expires. Until the proxy exists, expiry is the only real control.
- HMAC vs asymmetric: the data plane needs the key. That is a deploy
  problem (split later, Vault transit, etc.). Asymmetric would let
  the data plane hold only a public key; I will flip if a second
  replica of the data plane appears.

## Notes

Macaroons were tempting (caveats for row budgets). They are also how
you spend a week explaining attenuation to the on-call. Constraints
go in the claims. If I need attenuation I will add it as a third
ADR, not as a cute encoding.
