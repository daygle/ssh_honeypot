# Security Policy

## Supported Versions

Only the latest code on the `main` branch is supported. There are no long-term
supported releases - deploy from `main` (or the published
`ghcr.io/daygle/ssh_honeypot` image) to stay current.

## Reporting a Vulnerability

Please report security issues privately. Do not open a public GitHub issue for an
undisclosed vulnerability.

- Preferred: GitHub's private vulnerability reporting ("Security" tab -> "Report
  a vulnerability" on this repository).
- If that is unavailable, open a GitHub issue asking for a private contact
  channel and one will be provided.

Please include a description of the issue, steps to reproduce, the affected
component (honeypot, dashboard, Docker setup) and any suggested fix.

## What to Expect

- Acknowledgement within 7 days.
- A fix or mitigation plan for confirmed issues, typically within 30 days.
- Coordinated disclosure: please allow time for a fix before publishing details.

## Scope Notes

This project is a honeypot, so some behaviours look like security issues but are
intentional:

- The decoy SSH service never authenticates anyone and never opens a shell - all
  credentials are rejected and only recorded as evidence.
- The dashboard is intentionally unauthenticated by default (it contains honeypot
  telemetry only). If you expose it publicly, put it behind a reverse proxy with
  TLS and access control as described in the README.
- Recorded usernames and passwords are attacker guesses. Treat exports as
  sensitive data.
- The container is deliberately hardened: unprivileged user, read-only
  filesystem, dropped capabilities and `no-new-privileges`.

Out of scope:

- Denial-of-service against the honeypot port itself.
- Reports that the decoy SSH service "accepts connections" or "shows a login
  prompt" - that is the design.
- Issues in third-party dependencies with no demonstrated impact on this
  project. Those are best reported upstream; Dependabot tracks our dependencies.

## Dependency Updates

Dependabot opens weekly update PRs for the Python, Docker and GitHub Actions
dependencies. Vulnerabilities in dependencies that affect this project can also
be reported through the private channel above.
