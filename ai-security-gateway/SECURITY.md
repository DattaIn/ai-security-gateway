# Security Policy

## Scope

This is a portfolio/reference implementation, not a production
service processing real traffic or real secrets. That said, it's
built and reviewed to production-grade security standards, and
disclosure of real vulnerabilities is welcome.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security finding.
Instead, open a private security advisory via GitHub's
"Report a vulnerability" flow on this repository, or contact the
maintainer directly through the contact details on their GitHub
profile.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal request/payload is ideal)
- Any suggested remediation, if you have one

## What's explicitly out of scope for reports

- The heuristic prompt-injection detector being evadable by a novel
  paraphrase is a known, documented limitation (see
  `docs/threat-model.md`), not a vulnerability report — unless it
  demonstrates a bypass class not already discussed there.
- The reference deployment has no authentication layer by design
  (see `docs/design-decisions.md`); this is documented, not a bug.

## Supported versions

Only the `main` branch is maintained. There are no tagged releases
with independent security support at this time.
