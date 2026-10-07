# postern

Just-in-time access broker. A principal (human, workload, or AI agent)
asks for a resource, policy decides, and the grant expires.

This is a side project. The control plane, the evaluator, and the
ticket/cert minting are the parts I actually use. The data-plane proxy
is still a hole with a contract in front of it — I am not going to
dress a loopback echo up as a gateway.

## Why

I got tired of keeping two policy models: one for people (SSO + PAM)
and one for agents (tool allowlists bolted on afterwards). An agent
that can call `kubectl` is a principal. Treat it like one.

Postern is not a Boundary replacement and it is not a SPIRE
replacement. It is the piece that sits in between: short-lived
credentials, one evaluator, an audit log that fails closed.

## What it does today

- Deny-by-default grants in a small YAML DSL (`*`, `**`, `?`)
- Three principal kinds: `human`, `workload` (`spiffe://…`), `agent` (`agent://…`)
- Short-lived mTLS client certs (URI SAN = SPIFFE id, 24h hard ceiling)
- HMAC tickets bound to `{session, resource, action, exp}` for HTTP tool gateways
- Session recording flag + structured JSON audit log
- Agent constraints: tool, data class, row budget, `deny_exfil`

## What it does not do

- Replace your IdP. `/v1/grants` is unauthenticated. Bind it to
  loopback or put it behind something that already knows who you are.
- Speak WireGuard on the wire. Notes in `docs/architecture.md`.
- Persist sessions. Restart = everyone asks again. Fine for now.
- Detect prompt injection. That lives in front of the model. This
  repo is the authorization floor the detector cannot override.

## Quick start

```bash
go test ./...
go run ./cmd/postern -policy policies/examples/prod.yaml
```

In another shell:

```bash
go run ./cmd/posternctl grant \
  -kind workload \
  -principal spiffe://prod/ns/payments/sa/ledger \
  -action connect \
  -resource tcp://ledger-db.prod.internal:5432 \
  -ttl 5m \
  -network 10.8.12.4
```

Agent path (policy in `policies/examples/agents.yaml`):

```bash
go run ./cmd/postern -policy policies/examples/agents.yaml
go run ./cmd/posternctl grant \
  -kind agent \
  -principal agent://soc-triage \
  -action invoke \
  -resource mcp://splunk.query \
  -tool splunk.query \
  -data-class security-logs \
  -rows 20
```

## Policy

First matching grant wins. Put the tight ones first. An empty file
refuses to boot — that is a misconfig, not "deny all".

```yaml
version: 1
grants:
  - id: payments-ledger-db
    principal: {kind: workload, match: spiffe://prod/ns/payments/**}
    action: connect
    resource: tcp://ledger-db.prod.internal:5432
    max_ttl: 15m
    require:
      - network: "10.8.*"
    record_session: true
```

More in [`policies/examples/`](policies/examples/) and
[`docs/adr/0001-policy-language.md`](docs/adr/0001-policy-language.md).

## Layout

```
cmd/postern          control plane
cmd/posternctl       CLI
internal/policy      YAML + glob + evaluator
internal/identity    human / workload / agent
internal/certs       in-process CA (KMS later)
internal/ticket      HMAC ticket
internal/session     in-memory sessions, jittered TTL
internal/broker      HTTP API
internal/agentid     MCP-shaped helper
deploy/              k8s, helm, terraform
docs/                architecture, threat model, ADRs, one runbook
sdk/typescript       tiny client, no deps
```

## Status

I use the evaluator and the ticket mint in other experiments. Do not
point this at a production cluster and expect it to behave like
Teleport. If you do anyway, read `docs/threat-model.md` first and
keep `POSTERN_FAIL_CLOSED=true`.

## License

Apache-2.0
