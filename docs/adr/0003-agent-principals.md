# ADR 0003 — agents are a principal kind, not a flag on a user

Status: accepted
Date: 2026-04-02

## Context

Every "AI in prod" design I have been asked to review starts with a
human's token and then lets a chain of tools inherit it. That is how
you get a support bot with the same blast radius as the SRE who
installed it.

I also do not want a second policy system for tools. Two systems
drift. One of them will be the YAML file someone forgot to update.

## Decision

`KindAgent` with ids `agent://...`. Same evaluator, same audit log,
same tickets. Constraints that only make sense for tools (`max_rows`,
`deny_exfil`, `data_classes`) live on the grant and are copied onto
the ticket.

A glob on a human grant cannot match an agent id: the kind is checked
before the glob. This is the whole reason kind exists as a field
instead of a prefix convention.

## Consequences

- Onboarding an agent is "issue an id, write a grant", same as a
  workload. Platform teams already know that workflow.
- Prompt-injection mitigations stay out of this repo. They can deny
  *above* us. They must not be able to allow *around* us.
- Naming `agent://` is ugly. SPIFFE for agents (`spiffe://org/agent/...`)
  is probably where this ends up. The mint path already maps to a
  SPIFFE URI; renaming the wire id is a compatibility break I am
  willing to take later.

## Rejected

- Reuse the human's grant and add `on_behalf_of`. Confused deputy
  with extra steps.
- Separate "tool policy" CRD. See the first paragraph.
