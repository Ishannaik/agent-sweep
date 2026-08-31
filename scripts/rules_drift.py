#!/usr/bin/env python3
"""Rules-drift checker: compare agentsweep detection rules against upstream gitleaks.

Fetches the canonical gitleaks config and reports three buckets:

  DRIFTED       mapped gitleaks rule whose regex changed (or vanished) vs the
                committed snapshot in scripts/rules_snapshot.json
  UNMAPPED-NEW  gitleaks rules agentsweep does not cover at all (entries that
                appeared upstream since the snapshot are flagged as NEW)
  OK            mapped gitleaks rules whose regexes are unchanged

Drift is measured against the snapshot, NOT against our own regexes -- ours are
intentionally different shapes (tighter anchors, no capture-group conventions).

Usage:
    python scripts/rules_drift.py                 # markdown report; exit 1 on drift
    python scripts/rules_drift.py --dry-run       # same report; always exit 0
    python scripts/rules_drift.py --update-snapshot   # rewrite the snapshot baseline
    python scripts/rules_drift.py --toml-file F   # parse a local gitleaks.toml (no network)

Exit codes: 0 = no drift, 1 = drift found (DRIFTED non-empty, or unmapped rules
new since the snapshot), 2 = operational error.

Stdlib only. Requires Python 3.11+ for tomllib; CI runs it on 3.12.
This script is repo/CI tooling only -- the agentsweep CLI itself never touches
the network.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import urllib.request
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback guard
    tomllib = None

GITLEAKS_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "scripts" / "rules_snapshot.json"
SCANNER_PATH = REPO_ROOT / "src" / "agentsweep" / "scanner.py"
ISSUE_TITLE = "Detection rules drift vs gitleaks"

# Our rule id -> upstream gitleaks rule id, verified by hand against
# config/gitleaks.toml. None means we cover something gitleaks has no
# equivalent for. Note that one gitleaks rule can back several of ours
# (gitleaks "aws-access-token" matches AKIA and ASIA prefixes; their
# "stripe-access-token" covers sk/rk for test, live and prod).
OURS_TO_GITLEAKS: dict[str, str | None] = {
    "aws-access-key": "aws-access-token",
    "aws-session-token": "aws-access-token",
    "github-pat": "github-pat",
    "github-oauth": "github-oauth",
    "github-app": "github-app-token",
    "github-fine-grained": "github-fine-grained-pat",
    "stripe-live": "stripe-access-token",
    "stripe-test": "stripe-access-token",
    "openai": "openai-api-key",
    "anthropic": "anthropic-api-key",
    "google-api": "gcp-api-key",
    "slack-bot": "slack-bot-token",
    "slack-user": "slack-user-token",
    "slack-webhook": "slack-webhook-url",
    "huggingface": "huggingface-access-token",
    "jwt": "jwt",
    "private-key-pem": "private-key",
    "db-url-with-password": None,  # no generic DB-URL rule upstream
    "neon-role-password": None,  # no gitleaks equivalent
    "tavily-api-key": None,  # no gitleaks equivalent
    "npm-token": "npm-access-token",
    "pypi-token": "pypi-upload-token",
    "sendgrid": "sendgrid-api-token",
    "twilio": "twilio-api-key",
    "discord-bot-token": None,  # gitleaks ships no dedicated bot-token regex
    # --- ported from gitleaks (see the ported block in scanner.py) ---
    '1password-secret-key': '1password-secret-key',
    '1password-service-account-token': '1password-service-account-token',
    'adobe-client-secret': 'adobe-client-secret',
    'age-secret-key': 'age-secret-key',
    'airtable-pat': 'airtable-personnal-access-token',
    'alibaba-access-key-id': 'alibaba-access-key-id',
    'anthropic-admin-key': 'anthropic-admin-api-key',
    'artifactory-api-key': 'artifactory-api-key',
    'artifactory-reference-token': 'artifactory-reference-token',
    'atlassian-api-token': 'atlassian-api-token',
    'authress-service-client-key': 'authress-service-client-access-key',
    'aws-bedrock-api-key-long-lived': 'aws-amazon-bedrock-api-key-long-lived',
    'aws-bedrock-api-key-short-lived': 'aws-amazon-bedrock-api-key-short-lived',
    'azure-ad-client-secret': 'azure-ad-client-secret',
    'clickhouse-cloud-api-secret': 'clickhouse-cloud-api-secret-key',
    'clojars-api-token': 'clojars-api-token',
    'cloudflare-origin-ca-key': 'cloudflare-origin-ca-key',
    'curl-auth-header': 'curl-auth-header',
    'curl-auth-user': 'curl-auth-user',
    'databricks-api-token': 'databricks-api-token',
    'defined-networking-api-token': 'defined-networking-api-token',
    'digitalocean-access-token': 'digitalocean-access-token',
    'digitalocean-pat': 'digitalocean-pat',
    'digitalocean-refresh-token': 'digitalocean-refresh-token',
    'doppler-api-token': 'doppler-api-token',
    'duffel-api-token': 'duffel-api-token',
    'dynatrace-api-token': 'dynatrace-api-token',
    'easypost-api-token': 'easypost-api-token',
    'easypost-test-api-token': 'easypost-test-api-token',
    'facebook-page-token': 'facebook-page-access-token',
    'flutterwave-encryption-key': 'flutterwave-encryption-key',
    'flutterwave-public-key': 'flutterwave-public-key',
    'flutterwave-secret-key': 'flutterwave-secret-key',
    'flyio-token': 'flyio-access-token',
    'frameio-token': 'frameio-api-token',
    'github-refresh-token': 'github-refresh-token',
    'gitlab-cicd-job-token': 'gitlab-cicd-job-token',
    'gitlab-deploy-token': 'gitlab-deploy-token',
    'gitlab-feature-flag-client-token': 'gitlab-feature-flag-client-token',
    'gitlab-feed-token': 'gitlab-feed-token',
    'gitlab-incoming-mail-token': 'gitlab-incoming-mail-token',
    'gitlab-kubernetes-agent-token': 'gitlab-kubernetes-agent-token',
    'gitlab-oauth-app-secret': 'gitlab-oauth-app-secret',
    'gitlab-pat': 'gitlab-pat',
    'gitlab-pat-routable': 'gitlab-pat-routable',
    'gitlab-pipeline-trigger': 'gitlab-ptt',
    'gitlab-runner-registration': 'gitlab-rrt',
    'gitlab-runner-auth': 'gitlab-runner-authentication-token',
    'gitlab-runner-auth-routable': 'gitlab-runner-authentication-token-routable',
    'gitlab-scim': 'gitlab-scim-token',
    'gitlab-session-cookie': 'gitlab-session-cookie',
    'grafana-api-key': 'grafana-api-key',
    'grafana-cloud-token': 'grafana-cloud-api-token',
    'grafana-service-account': 'grafana-service-account-token',
    'harness': 'harness-api-key',
    'terraform-api-token': 'hashicorp-tf-api-token',
    'heroku-api-key': 'heroku-api-key-v2',
    'huggingface-org': 'huggingface-organization-api-token',
    'infracost': 'infracost-api-token',
    'intra42-client-secret': 'intra42-client-secret',
    'jwt-base64': 'jwt-base64',
    'linear-api-key': 'linear-api-key',
    'mailgun-private-token': 'mailgun-private-api-token',
    'mailgun-public-key': 'mailgun-pub-key',
    'mailgun-signing-key': 'mailgun-signing-key',
    'mapbox-api-token': 'mapbox-api-token',
    'maxmind-license-key': 'maxmind-license-key',
    'microsoft-teams-webhook': 'microsoft-teams-webhook',
    'new-relic-browser-token': 'new-relic-browser-api-token',
    'new-relic-insert-key': 'new-relic-insert-key',
    'new-relic-user-key': 'new-relic-user-api-key',
    'notion-api-token': 'notion-api-token',
    'octopus-deploy-api-key': 'octopus-deploy-api-key',
    'openshift-user-token': 'openshift-user-token',
    'perplexity-api-key': 'perplexity-api-key',
    'plaid-access-token': 'plaid-api-token',
    'planetscale-api-token': 'planetscale-api-token',
    'planetscale-oauth-token': 'planetscale-oauth-token',
    'planetscale-password': 'planetscale-password',
    'postman-api-key': 'postman-api-token',
    'prefect-api-key': 'prefect-api-token',
    'pulumi-access-token': 'pulumi-api-token',
    'readme-api-token': 'readme-api-token',
    'rubygems-api-key': 'rubygems-api-token',
    'scalingo-api-token': 'scalingo-api-token',
    'sendinblue-api-key': 'sendinblue-api-token',
    'sentry-org-token': 'sentry-org-token',
    'sentry-user-token': 'sentry-user-token',
    'settlemint-app-token': 'settlemint-application-access-token',
    'settlemint-pat': 'settlemint-personal-access-token',
    'settlemint-sat': 'settlemint-service-access-token',
    'shippo': 'shippo-api-token',
    'shopify-access-token': 'shopify-access-token',
    'shopify-custom-access-token': 'shopify-custom-access-token',
    'shopify-private-app-token': 'shopify-private-app-access-token',
    'shopify-shared-secret': 'shopify-shared-secret',
    'sidekiq-secret': 'sidekiq-secret',
    'sidekiq-sensitive-url': 'sidekiq-sensitive-url',
    'slack-app-token': 'slack-app-token',
    'slack-config-access-token': 'slack-config-access-token',
    'slack-config-refresh-token': 'slack-config-refresh-token',
    'slack-legacy-token': 'slack-legacy-token',
    'slack-legacy-workspace-token': 'slack-legacy-workspace-token',
    'snyk': 'snyk-api-token',
    'square-access-token': 'square-access-token',
    'telegram-bot-token': 'telegram-bot-api-token',
    'typeform-token': 'typeform-api-token',
    'vault-batch-token': 'vault-batch-token',
    'vault-service-token': 'vault-service-token',
    # --- gitleaks port wave 2 ---
    'adafruit-api-key': 'adafruit-api-key',
    'airtable-api-key': 'airtable-api-key',
    'algolia-api-key': 'algolia-api-key',
    'asana-client-id': 'asana-client-id',
    'asana-client-secret': 'asana-client-secret',
    'beamer-api-token': 'beamer-api-token',
    'bitbucket-client-id': 'bitbucket-client-id',
    'bitbucket-client-secret': 'bitbucket-client-secret',
    'bittrex-access-key': 'bittrex-access-key',
    'codecov-access-token': 'codecov-access-token',
    'coinbase-access-token': 'coinbase-access-token',
    'confluent-access-token': 'confluent-access-token',
    'confluent-secret-key': 'confluent-secret-key',
    'contentful-delivery-api-token': 'contentful-delivery-api-token',
    'datadog-access-token': 'datadog-access-token',
    'discord-api-token': 'discord-api-token',
    'dropbox-api-token': 'dropbox-api-token',
    'dropbox-long-lived-api-token': 'dropbox-long-lived-api-token',
    'dropbox-short-lived-api-token': 'dropbox-short-lived-api-token',
    'droneci-access-token': 'droneci-access-token',
    'fastly-api-token': 'fastly-api-token',
    'finicity-client-secret': 'finicity-client-secret',
    'finnhub-access-token': 'finnhub-access-token',
    'flickr-access-token': 'flickr-access-token',
    'freemius-secret-key': 'freemius-secret-key',
    'freshbooks-access-token': 'freshbooks-access-token',
    'gitter-access-token': 'gitter-access-token',
    'gocardless-api-token': 'gocardless-api-token',
    'heroku-api-key-legacy': 'heroku-api-key',
    'intercom-api-key': 'intercom-api-key',
    'jfrog-api-key': 'jfrog-api-key',
    'jfrog-identity-token': 'jfrog-identity-token',
    'kraken-access-token': 'kraken-access-token',
    'kucoin-access-token': 'kucoin-access-token',
    'kucoin-secret-key': 'kucoin-secret-key',
    'launchdarkly-access-token': 'launchdarkly-access-token',
    'lob-api-key': 'lob-api-key',
    'lob-pub-api-key': 'lob-pub-api-key',
    'mailchimp-api-key': 'mailchimp-api-key',
    'mattermost-access-token': 'mattermost-access-token',
    'messagebird-api-token': 'messagebird-api-token',
    'messagebird-client-id': 'messagebird-client-id',
    'netlify-access-token': 'netlify-access-token',
    'sendbird-access-id': 'sendbird-access-id',
    'sonar-api-token': 'sonar-api-token',
    'sourcegraph-access-token': 'sourcegraph-access-token',
    'squarespace-access-token': 'squarespace-access-token',
    'travisci-access-token': 'travisci-access-token',
    'twitch-api-token': 'twitch-api-token',
    'twitter-access-secret': 'twitter-access-secret',
    'twitter-access-token': 'twitter-access-token',
    'twitter-api-key': 'twitter-api-key',
    'twitter-api-secret': 'twitter-api-secret',
    'twitter-bearer-token': 'twitter-bearer-token',
    'yandex-api-key': 'yandex-api-key',
    'yandex-aws-access-token': 'yandex-aws-access-token',
    'yandex-oauth-access-token': 'yandex-access-token',
}


def fetch_gitleaks_toml(url: str = GITLEAKS_URL) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "agentsweep-rules-drift"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_rules(toml_text: str) -> dict[str, dict]:
    """Return {rule_id: {"regex": str | None, "description": str}}."""
    data = tomllib.loads(toml_text)
    rules: dict[str, dict] = {}
    for entry in data.get("rules", []):
        rid = entry.get("id")
        if not rid:
            continue
        rules[rid] = {
            "regex": entry.get("regex"),  # a few rules are path-only
            "description": entry.get("description", ""),
        }
    return rules


def local_rule_ids() -> list[str] | None:
    """Best-effort load of RULES ids from src/agentsweep/scanner.py."""
    try:
        import importlib.util

        spec = importlib.util.spec_from_file_location("_agentsweep_scanner", SCANNER_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return [rule_id for rule_id, _display, _pattern in mod.RULES]
    except Exception:
        return None


def load_snapshot() -> dict | None:
    if not SNAPSHOT_PATH.exists():
        return None
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def build_snapshot(upstream: dict[str, dict]) -> dict:
    mapped_ids = sorted({g for g in OURS_TO_GITLEAKS.values() if g})
    return {
        "source": GITLEAKS_URL,
        "updated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mapped_regexes": {
            gid: upstream[gid]["regex"] for gid in mapped_ids if gid in upstream
        },
        "unmapped_ids": sorted(set(upstream) - set(mapped_ids)),
    }


def write_snapshot(snapshot: dict) -> None:
    SNAPSHOT_PATH.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def gitleaks_to_ours() -> dict[str, list[str]]:
    rev: dict[str, list[str]] = {}
    for ours, gid in OURS_TO_GITLEAKS.items():
        if gid:
            rev.setdefault(gid, []).append(ours)
    return rev


def compare(upstream: dict[str, dict], snapshot: dict) -> dict:
    rev = gitleaks_to_ours()
    snap_regexes: dict = snapshot.get("mapped_regexes", {})
    snap_unmapped = set(snapshot.get("unmapped_ids", []))

    drifted: list[dict] = []
    ok: list[str] = []
    for gid in sorted(rev):
        current = upstream.get(gid, {}).get("regex") if gid in upstream else None
        baseline = snap_regexes.get(gid)
        if gid not in upstream:
            drifted.append({"id": gid, "kind": "removed upstream",
                            "old": baseline, "new": None})
        elif baseline is None:
            drifted.append({"id": gid, "kind": "not in snapshot",
                            "old": None, "new": current})
        elif current != baseline:
            drifted.append({"id": gid, "kind": "regex changed",
                            "old": baseline, "new": current})
        else:
            ok.append(gid)

    unmapped = sorted(set(upstream) - set(rev))
    new_unmapped = sorted(set(unmapped) - snap_unmapped)
    return {
        "drifted": drifted,
        "ok": ok,
        "unmapped": unmapped,
        "new_unmapped": new_unmapped,
    }


def render_report(result: dict, upstream: dict[str, dict], snapshot: dict,
                  baseline_created: bool, unmapped_local: list[str]) -> str:
    rev = gitleaks_to_ours()
    drifted = result["drifted"]
    ok = result["ok"]
    unmapped = result["unmapped"]
    new_unmapped = result["new_unmapped"]
    local_only = sorted(o for o, g in OURS_TO_GITLEAKS.items() if g is None)

    lines: list[str] = []
    lines.append(f"# {ISSUE_TITLE}")
    lines.append("")
    lines.append(f"- Upstream: [{GITLEAKS_URL}]({GITLEAKS_URL}) - {len(upstream)} rules")
    lines.append(f"- Snapshot: `scripts/rules_snapshot.json` (taken {snapshot.get('updated', '?')})")
    lines.append(
        f"- Mapping: {sum(1 for g in OURS_TO_GITLEAKS.values() if g)} agentsweep rules"
        f" -> {len(rev)} gitleaks rules"
        f" ({len(local_only)} local-only: {', '.join(f'`{o}`' for o in local_only)})"
    )
    if baseline_created:
        lines.append("- Note: snapshot was missing; an initial baseline was just created.")
    if unmapped_local:
        lines.append(
            "- WARNING: local rules missing from OURS_TO_GITLEAKS in scripts/rules_drift.py: "
            + ", ".join(f"`{r}`" for r in unmapped_local)
        )
    lines.append("")

    lines.append(f"## DRIFTED ({len(drifted)})")
    lines.append("")
    if not drifted:
        lines.append("No mapped gitleaks regex changed since the snapshot.")
    for d in drifted:
        ours = ", ".join(f"`{o}`" for o in rev.get(d["id"], []))
        lines.append(f"### `{d['id']}` - {d['kind']} (backs our rule(s): {ours})")
        lines.append("")
        lines.append("```")
        lines.append(f"snapshot: {d['old']}")
        lines.append(f"current:  {d['new']}")
        lines.append("```")
        lines.append("")
    lines.append("")

    lines.append(f"## UNMAPPED-NEW ({len(unmapped)})")
    lines.append("")
    lines.append(f"Gitleaks rules agentsweep does not cover. "
                 f"{len(new_unmapped)} appeared upstream since the snapshot.")
    lines.append("")
    if new_unmapped:
        lines.append("New since snapshot:")
        lines.append("")
        for gid in new_unmapped:
            desc = upstream.get(gid, {}).get("description", "")
            lines.append(f"- `{gid}` - {desc}")
        lines.append("")
    lines.append("<details>")
    lines.append(f"<summary>All {len(unmapped)} uncovered gitleaks rules</summary>")
    lines.append("")
    for gid in unmapped:
        desc = upstream.get(gid, {}).get("description", "")
        lines.append(f"- `{gid}` - {desc}")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    lines.append(f"## OK ({len(ok)})")
    lines.append("")
    lines.append("| gitleaks rule | backs agentsweep rule(s) |")
    lines.append("| --- | --- |")
    for gid in ok:
        lines.append(f"| `{gid}` | {', '.join(f'`{o}`' for o in rev.get(gid, []))} |")
    lines.append("")
    lines.append("---")
    lines.append("After porting/adjusting rules, refresh the baseline with "
                 "`python scripts/rules_drift.py --update-snapshot` and commit "
                 "`scripts/rules_snapshot.json`.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true",
                        help="print the report but always exit 0")
    parser.add_argument("--update-snapshot", action="store_true",
                        help="rewrite scripts/rules_snapshot.json from upstream and exit")
    parser.add_argument("--toml-file", metavar="PATH",
                        help="parse a local gitleaks.toml instead of fetching")
    args = parser.parse_args(argv)

    # Keep markdown output stable when stdout is redirected (Windows cp1252 etc.).
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    if tomllib is None:
        print("error: rules_drift.py needs Python 3.11+ (tomllib); CI uses 3.12.",
              file=sys.stderr)
        return 2

    try:
        if args.toml_file:
            toml_text = Path(args.toml_file).read_text(encoding="utf-8")
        else:
            toml_text = fetch_gitleaks_toml()
    except OSError as exc:
        print(f"error: could not load gitleaks.toml: {exc}", file=sys.stderr)
        return 2

    try:
        upstream = parse_rules(toml_text)
    except tomllib.TOMLDecodeError as exc:
        print(f"error: could not parse gitleaks.toml: {exc}", file=sys.stderr)
        return 2
    if not upstream:
        print("error: parsed 0 rules from gitleaks.toml; aborting.", file=sys.stderr)
        return 2

    if args.update_snapshot:
        write_snapshot(build_snapshot(upstream))
        print(f"snapshot written: {SNAPSHOT_PATH} "
              f"({len(upstream)} upstream rules)")
        return 0

    baseline_created = False
    snapshot = load_snapshot()
    if snapshot is None:
        snapshot = build_snapshot(upstream)
        write_snapshot(snapshot)
        baseline_created = True

    # Consistency check: every local rule id should appear in the mapping.
    unmapped_local: list[str] = []
    ids = local_rule_ids()
    if ids is not None:
        unmapped_local = sorted(set(ids) - set(OURS_TO_GITLEAKS))

    result = compare(upstream, snapshot)
    report = render_report(result, upstream, snapshot, baseline_created, unmapped_local)
    print(report)

    drift_found = bool(result["drifted"]) or bool(result["new_unmapped"])
    if args.dry_run:
        return 0
    return 1 if drift_found else 0


if __name__ == "__main__":
    sys.exit(main())
