# Architecture

Postern is a control plane. It decides whether a principal may touch a
resource, for how long, and under which constraints. It then mints two
things the data plane can enforce without calling home on every packet:

1. A short-lived client certificate (URI SAN = SPIFFE id)
2. An HMAC ticket bound to `{session, resource, action, exp}`

```
  human / workload / agent
              |
              |  POST /v1/grants
              v
        +-----------+      policy yaml
        | posternd  | <--- first match, deny by default
        +-----------+
           |      |
      cert+ticket |  audit jsonl  (fail-closed)
           v      v
        data plane (today: the caller; tomorrow: a proxy)
```

The data-plane proxy is not done. I am not going to pretend a loopback
echo server is a WireGuard gateway. The ticket verifier is the contract
that proxy will sit on.

## Trust boundaries

| Boundary | What crosses it | What must not |
|---|---|---|
| Client → control plane | grant request, identity proof | long-lived keys |
| Control plane → data plane | ticket, client cert, CA | policy source, ticket HMAC key |
| Agent → tool | ticket + scoped tool call | raw IdP tokens, production secrets |

The ticket HMAC key never leaves the control plane. The CA private key
neither. Today both live in process memory because this is a laptop
project; the `certs.CA` and `ticket.Mint` types are the seams for KMS
and Vault.

## Policy

See [adr/0001-policy-language.md](adr/0001-policy-language.md).

Evaluator is first-match. Tight grants go at the top of the file. An
empty grant list is a misconfiguration, not "deny all" — I want that
to fail the process at boot, not silently lock everyone out (or worse,
be mistaken for a successful load of an empty file after a truncated
edit).

## Identity

Three kinds, no hybrids:

- `human` — email-shaped, OIDC at the edge (not implemented here)
- `workload` — `spiffe://...`
- `agent` — `agent://...`, mapped onto `spiffe://postern/agent/...` when we mint

Agents are not "a user with extra attributes". They get their own kind
so a grant for `rafa@corp.example` can never accidentally cover
`agent://soc-triage` because someone globbed `*`.

## Sessions

In-memory map, expiry sweeper, explicit revoke. TTL is jittered by ~10%
so a fleet that connected together does not reconnect together.

## What I would not ship yet

- Persistence. Restart = drop sessions. Fine for a demo, not for a SOC.
- mTLS on the control plane listener. `POSTERN_LISTEN` defaults to loopback.
- A real data-plane proxy. Ticket verify is the stand-in.
- OIDC / WebAuthn. The `require: mfa:` field is checked against attrs
  the caller asserts. In production the control plane must observe MFA
  itself, not trust a client-supplied string. I left the hook in so the
  policy language does not have to change.
