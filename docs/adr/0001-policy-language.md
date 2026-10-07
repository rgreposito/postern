# ADR 0001 — a small YAML DSL, not Rego

Status: accepted
Date: 2026-03-18

## Context

I need humans, workloads, and agents to share one evaluator. OPA/Rego
is the default suggestion and I have shipped it. It is also how a
policy file becomes a programming language that three people in the
company can read.

Grant tables I care about look like: principal, action, resource, ttl,
a handful of constraints.

## Decision

A YAML document of grants. First match wins. Glob syntax is `*`, `**`,
`?`. No character classes, no negation in the matcher (deny is the
default, you do not need `not`).

## Consequences

- Adding a new constraint is a struct field and a test, not a new
  builtin.
- You cannot express "allow if label X unless namespace Y". Good.
  Push that into two grants, tight one first.
- Porting to OPA later is possible because the document is data. The
  other direction is how you end up with a 400-line `system.authz`.

## Rejected alternatives

- Cedar: nicer than Rego, still a second language to hire for.
- Cedar-via-WASM: not on a Sunday.
- "Just use OPA, everyone knows it": everyone says they know it.
