# Security

Please do **not** open a public issue for anything that mints
credentials, evaluates grants, or handles the ticket HMAC key.

Email: giove.raffaele.io@gmail.com

I aim to reply within 72 hours. If I do not, a second mail with
`[nudge]` in the subject is fine.

Things I will take seriously, in order:

1. A grant that succeeds without a matching rule
2. A ticket that verifies after expiry, or against the wrong resource
3. A client cert with a TTL above the 24h ceiling
4. Anything that turns fail-closed into fail-open without it being
   obvious in the audit log

Please include a failing test if you can. I will write one if you
cannot.

This is a personal project. There is no bug bounty.
