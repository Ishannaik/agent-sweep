# Releasing agentsweep

## One-time setup: configure trusted publishing on PyPI

1. Create the `agentsweep` project on PyPI (https://pypi.org/manage/projects/) if it does not exist yet.
2. Go to **Manage > Publishing** for the project and add a new trusted publisher:
   - Publisher: **GitHub Actions**
   - Owner: `Ishannaik`
   - Repository: `agent-sweep`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
3. In the GitHub repo, create an Actions **environment** named `pypi` (Settings > Environments).

Full documentation: https://docs.pypi.org/trusted-publishers/

No API token or secret is required - PyPI authenticates via OIDC from the workflow.

## Per-release steps

1. Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading, and add the compare link at the
   bottom of the file (`[X.Y.Z]: .../compare/vPREV...vX.Y.Z`). Leave a
   fresh empty `## [Unreleased]` section above it for the next release.

2. Bump the version in two places:
   - `pyproject.toml` - the `version = "X.Y.Z"` field
   - `src/agentsweep/__init__.py` - the `__version__ = "X.Y.Z"` string

3. Commit the version bump and changelog together:
   ```
   git add pyproject.toml src/agentsweep/__init__.py CHANGELOG.md
   git commit -m "chore: bump version to X.Y.Z"
   ```

4. Tag and push:
   ```
   git tag vX.Y.Z
   git push origin main --tags
   ```

Pushing the tag triggers `release.yml`, which builds the sdist and wheel and publishes them to PyPI automatically.

## After first publish

Users can install agentsweep with:

```
pip install agentsweep
```

or, without a prior install, run it directly with uv:

```
uvx agentsweep
```
