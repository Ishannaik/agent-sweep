# Security policy

agent-sweep reads and rewrites files that can hold live credentials, so security reports get priority over everything else in this repo.

## Supported versions

Only the latest release on PyPI (`agentsweep`) gets security fixes. Upgrade before you report, in case the issue is already fixed.

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Report it privately through GitHub: go to the [Security tab](https://github.com/Ishannaik/agent-sweep/security) and click **Report a vulnerability**. If that doesn't work for you, email ishan.naik7@gmail.com with "agent-sweep security" in the subject.

Please include:

- the agent-sweep version and how you installed it
- your OS and the agent CLI involved, if any
- steps to reproduce, and what you expected to happen
- whether a secret could leak, survive a scan it should have been removed by, or get corrupted

## What counts

- A secret that agent-sweep reports as removed but that stays on disk
- agent-sweep writing a secret somewhere new (logs, backups, temp files, stdout)
- A crafted history file that makes agent-sweep run code, read outside the paths it should, or destroy data
- A problem in how releases are built or published

Missed detections of a new secret format are welcome too, but they are ordinary bugs: open a normal issue without the secret itself.

## What happens next

- I reply within 3 days to confirm I got it.
- I aim to ship a fix within 14 days for anything that leaks or keeps a secret, and keep you updated until then.
- Once a fix is released, I publish a GitHub security advisory and credit you, unless you ask not to be named.
