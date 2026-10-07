# Threat model

Scoped to the control plane and the ticket. The missing data-plane
proxy is called out as an assumption, not a control.

## Assumptions

- Callers of `/v1/grants` are already authenticated. This repo does not
  implement OIDC. If you expose the port, you have no authn.
- Policy files are deployed through the same path as the binary
  (git + CI), not edited on the box.
- Ticket HMAC key is 32+ bytes and not the dev fallback.

## Assets

- Ticket HMAC key
- CA private key
- Policy document
- Audit log
- Live session table

## Threats I actually care about

### Confused deputy (agents)

An agent is given `mcp://splunk.query` and a row budget. A prompt that
says "export this to the public ticket" is an exfil attempt. The grant
carries `deny_exfil: true` and the ticket echoes it so the tool gateway
can refuse even if the agent lies in a later call.

This is not a prompt-injection detector. Those belong in front of the
model. This is the authorization floor the detector cannot override.

### Ticket replay

Tickets have `nbf` / `exp` and are bound to a resource. Replay against
a different resource fails `ErrAudience`. Replay after expiry fails
`ErrExpired`. Replay inside the window against the same resource is
accepted — that is a session, not a one-shot token. If you want
one-shot, revoke on first use; I have not done that because the data
plane is not here yet to tell us "first use" happened.

### Grant that outlives intent

Hard ceiling of 24h in `certs.Mint`, regardless of policy. Jitter on
TTL. Explicit revoke. No refresh endpoint; the client asks again and
goes back through policy.

### Empty or truncated policy

Boot fails. There is no "fail open if the file is empty". There is also
no "fail closed with zero grants" because that is indistinguishable
from "I deployed the wrong file" until the pages start.

### Audit hole

`failClosed` (default true): if the audit writer errors, the grant is
aborted and the session revoked. I would rather page on a full disk
than explain a missing trail in an incident.

### Clock skew

Client certs are valid 30 seconds in the past. Not an hour. An hour is
how you get "expired" certs that still work on a box with a bad clock,
which is indistinguishable from replay.

## Out of scope (for now)

- Physical access to the control plane host
- Quantum computers vs P-256. If I ever mint with a post-quantum
  hybrid it will be a new CA, not a flag. Notes only.
- The identity provider
