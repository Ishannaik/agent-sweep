# Security Policy

agentsweep reads and rewrites AI coding agent histories, which often hold real
secrets. We treat any bug that could leak a secret, skip a redaction, corrupt a
history file, or make an outbound network call as high priority.

## Supported versions

Only the latest release on PyPI and the `main` branch get security fixes.
Please check that an issue still happens on the latest release or `main`
before you report it.

| Version                  | Supported |
| ------------------------ | --------- |
| Latest release / `main`  | Yes       |
| Older releases           | No        |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a
security problem.**

Report it privately in one of these ways:

- **Preferred:** GitHub private vulnerability reporting. Open the
  [Security tab](https://github.com/Ishannaik/agent-sweep/security), click
  **Report a vulnerability**, or go straight to
  <https://github.com/Ishannaik/agent-sweep/security/advisories/new>.
- **Email:** `ishannaik7@gmail.com`

Please include:

- What the problem is and its impact.
- Steps to reproduce, or a proof of concept. Use synthetic secrets only,
  never real credentials.
- The agentsweep version (`agentsweep --version`), your OS and Python version.

## What to expect

- We acknowledge your report within **7 days**.
- We tell you whether we confirm the issue, and keep you updated while we
  work on a fix.
- We credit you in the release notes unless you prefer to stay anonymous.

Please give us a reasonable window to ship a fix before you disclose the
issue publicly.
