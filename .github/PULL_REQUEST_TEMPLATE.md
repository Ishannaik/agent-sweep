<!--
Thanks for contributing to agentsweep! Fill in the sections below.
Keep PRs focused — one concern per PR (a CI fix and a feature should be
two PRs). See CLAUDE.md for the project's conventions.
-->

## What & why

<!-- One or two sentences: what this changes and why. Link any issue, e.g. "Closes #12". -->

## Type of change

- [ ] Bug fix
- [ ] New agent source
- [ ] New detection rule
- [ ] Feature / enhancement
- [ ] Refactor / docs / chore

## Testing

<!-- How did you verify this? Paste the relevant `pytest` summary. -->

```
# pytest output here
```

## Checklist

- [ ] `pytest` passes locally, and CI is green on **all** platforms (Linux **and** Windows, Python 3.11–3.13)
- [ ] No real secrets, tokens, or raw history-file contents are committed — tests use synthetic, non-live examples
- [ ] Redaction / write-path changes preserve the corruption-prevention invariants (path containment, atomic replace, mandatory no-clobber backup, post-write validation, line-count preservation, audit trail)
- [ ] **New detection rule?** Added to `RULES` **and** `ROTATION_GUIDANCE` **and** a fixture/test, with every regex quantifier bounded (no unbounded `.*`), and the keyword pre-filter kept lossless
- [ ] **New source?** Registered in `SOURCES` with process markers, a menu entry, and a round-trip test (see CLAUDE.md → "Adding a new Source")
- [ ] `--json` and non-tty output stay machine-clean (no banners / styling, no `ui` import on those paths)
- [ ] Did not re-introduce `force-include` in `pyproject.toml`
