# Runbook: grant denied

The API returned 403. Before you add a grant, read the reason.

## 1. Read the audit line

```
jq 'select(.type=="grant.deny")' /var/log/postern/audit.jsonl | tail
```

`reason` is one of:

| reason | what it actually means |
|---|---|
| `no matching grant` | kind/id/action/resource glob missed. 90% of tickets. |
| `requirement not met: mfa ...` | caller asserted the wrong attr, *or* the IdP hop is missing. |
| `constraint violation: ...` | agent asked for exfil / too many rows / wrong data class. |
| `incomplete request` | client bug. |

## 2. Test the glob without deploying

```
go test ./internal/policy -run TestMatch -v
```

or, faster, drop a one-off in `eval_test.go`. Do not "fix" a deny by
widening `**` on a Friday.

## 3. Kind mismatch

`rafa@corp.example` will never match a workload grant. Agents will
never match a human grant. If someone wants a bot to "act as them",
that is a new principal, not a flag.

## 4. Still stuck

Dump the request the client sent (it is in the audit line) and the
grant they *thought* they were hitting. Diff kind, then match, then
action, then resource, in that order. I have lost hours doing it the
other way around.
