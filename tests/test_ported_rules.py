"""Tests for the detection rules ported from the gitleaks rule pack.

FIXTURES embeds one synthetic (non-live) example secret per ported rule and
asserts the full scan pipeline -- including overlap dedupe -- attributes it
to the right rule id.
"""
from __future__ import annotations

import re
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentsweep.scanner import ROTATION_GUIDANCE, RULES, scan_text  # noqa: E402


# Fixture values are split into adjacent string literals on purpose:
# the file must never contain a contiguous secret-shaped token, or
# GitHub push protection (and other scanners) will flag the repo.
FIXTURES: dict[str, str] = {
    '1password-secret-key': 'A3-A1B2C3-D4E5F6-G7H' '8I-J9K0L-M1N2O-P3Q4R',
    # NOTE: fixture extended to 252 chars after the prefix -- the upstream
    # sample was 246, short of the regex's {250,} minimum.
    '1password-service-account-token': 'ops_eyJ' + 'a1b2c3' * 42,
    'adobe-client-secret': 'p8e-a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3d4',
    'age-secret-key': 'AGE-SECRET-KEY-1QPZRY9X8GFQPZRY9X8GFQ' 'PZRY9X8GFQPZRY9X8GFQPZRY9X8GF2TVDW0S3',
    'airtable-pat': 'patA1b2C3d4E5f6Gh.a1b2c3d4a1b2c3d4a1b2c3d' '4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4',
    'alibaba-access-key-id': 'LTAIa1b2c3a1' 'b2c3a1b2c3d4',
    'anthropic-admin-key': 'sk-ant-admin01-a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1bAA',
    'artifactory-api-key': 'AKCpa1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3d4e',
    'artifactory-reference-token': 'cmVmda1b2c3a1b2c3a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3d4e5f',
    'atlassian-api-token': 'ATATT3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'authress-service-client-key': 'sc_a1b2c3d4e5.a1b2.acc_a1b2c3d4e5' 'f6.a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'aws-bedrock-api-key-long-lived': 'ABSKa1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'aws-bedrock-api-key-short-lived': 'bedrock-api-key-YmVkcm' '9jay5hbWF6b25hd3MuY29t',
    'azure-ad-client-secret': 'abc1Q~a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3d',
    'clickhouse-cloud-api-secret': '4b1da1b2c3a1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3d4',
    'clojars-api-token': 'CLOJARS_a1b2c3a1b2c3a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'cloudflare-origin-ca-key': 'v1.0-a1b2c3a1b2c3a1b2c3a1b2c3-a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1',
    'cohere-api-key': 'cohere_api_key = a1b2c3d4e5a1b2c3d4e5' 'a1b2c3d4e5a1b2c3d4e5',
    'curl-auth-header': 'curl -H "Authorization: B' 'earer a1b2c3a1b2c3a1b2c3"',
    'curl-auth-user': 'curl --user apiu' 'ser1:a1b2c3a1b2c3',
    'databricks-api-token': 'dapia1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1',
    'deepseek-api-key': 'deepseek_api_key = sk-a1b2c3d4e5f6a1b2c3d4' 'e5f6a1b2c3d4',
    'defined-networking-api-token': 'dnkey-a1b2c3a1b2c3a1b2c3a1b2c3a1-a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'digitalocean-access-token': 'doo_v1_a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'digitalocean-pat': 'dop_v1_a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'digitalocean-refresh-token': 'dor_v1_a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'doppler-api-token': 'dp.pt.a1b2c3a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3a1b2c3a',
    'duffel-api-token': 'duffel_test_a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3a',
    'dynatrace-api-token': 'dt0c01.a1b2c3a1b2c3a1b2c3a1b2c3.a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'easypost-api-token': 'EZAKa1b2c3a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'easypost-test-api-token': 'EZTKa1b2c3a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'facebook-page-token': 'EAAMa1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'fireworks-api-key': 'fireworks_api_key = fw_a1b2c3d4e5a1b2c3d4e5' 'a1b2',
    'flutterwave-encryption-key': 'FLWSECK_TEST' '-a1b2c3a1b2c3',
    'flutterwave-public-key': 'FLWPUBK_TEST-a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3ab-X',
    'flutterwave-secret-key': 'FLWSECK_TEST-a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3ab-X',
    'flyio-token': 'fo1_a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3d',
    'frameio-token': 'fio-u-a1b2c3a1b2c3a1b2c3a1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'github-refresh-token': 'ghr_a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3',
    'gitlab-cicd-job-token': 'glcbt-64_a1b2c' '3a1b2c3a1b2c3ab',
    'gitlab-deploy-token': 'gldt-a1b2c3a' '1b2c3a1b2c3ab',
    'gitlab-feature-flag-client-token': 'glffct-a1b2c3' 'a1b2c3a1b2c3ab',
    'gitlab-feed-token': 'glft-a1b2c3a' '1b2c3a1b2c3ab',
    'gitlab-incoming-mail-token': 'glimt-a1b2c3a1b' '2c3a1b2c3a1b2c3d',
    'gitlab-kubernetes-agent-token': 'glagent-a1b2c3a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3de',
    'gitlab-oauth-app-secret': 'gloas-a1b2c3a1b2c3a1b2c3a1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'gitlab-pat': 'glpat-a1b2c3a' '1b2c3a1b2c3ab',
    'gitlab-pat-routable': 'glpat-a1b2c3a1b2c3a1b2c' '3a1b2c3a1b2c3.a1b2c3a1b',
    'gitlab-pipeline-trigger': 'glptt-a1b2c3a1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3a1b2',
    'gitlab-runner-registration': 'GR1348941a1b2c' '3a1b2c3a1b2c3a1',
    'gitlab-runner-auth': 'glrt-a1b2c3a' '1b2c3a1b2c3a1',
    'gitlab-runner-auth-routable': 'glrt-t1_a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3.a1b2c3a1b',
    'gitlab-scim': 'glsoat-a1b2c3' 'a1b2c3a1b2c3a1',
    'gitlab-session-cookie': '_gitlab_session=a1b2c3a1' 'b2c3a1b2c3a1b2c3a1b2c3a1',
    'google-oauth-client-secret': 'GOCSPX-a1b2c3d4e5f6a1b2' 'c3d4e5f6a1b2',
    'google-service-account-key': '{"type": "service_account", "private_key_id": "' 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}',
    'grafana-api-key': 'eyJrIjoia1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'grafana-cloud-token': 'glc_a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3',
    'grafana-service-account': 'glsa_a1b2c3a1b2c3a1b2c3' 'a1b2c3a1b2c3a1_a1b2c3a1',
    'groq-api-key': 'gsk_a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5' 'a1b2c3d4e5a1',
    'harness': 'pat.a1b2c3a1b2c3a1b2c3a1b2.a1b2c3a1b' '2c3a1b2c3a1b2c3.a1b2c3a1b2c3a1b2c3a1',
    'terraform-api-token': 'a1b2c3a1b2c3a1.atlasv1.a1b2c3a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'heroku-api-key': 'HRKU-AAa1b2c3a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'huggingface-org': 'api_org_abcdefabcdefa' 'bcdefabcdefabcdefabcd',
    'infracost': 'ico-a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1',
    'intra42-client-secret': 's-s4t2ud-a1b2c3d4a1b2c3d4a1b2c3d4a1b' '2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4',
    'jwt-base64': 'ZXlKaGJHY2lPaUa1b2c3a1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'linear-api-key': 'lin_api_a1b2c3d4e5a1b2c3' 'd4e5a1b2c3d4e5a1b2c3d4e5',
    'mailgun-private-token': 'mailgun_key = key-a1b2c3d' '4e5f6a1b2c3d4e5f6a1b2c3d4',
    'mailgun-public-key': 'mailgun_pubkey = pubkey-a1b2' 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
    'mailgun-signing-key': 'mailgun_signing_key = a1b2c3d4a1b2c3' 'd4a1b2c3d4a1b2c3d4-a1b2c3d4-a1b2c3d4',
    'mapbox-api-token': 'pk.a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5' 'a1b2c3d4e5a1b2c3d4e5.a1b2c3d4e5a1b2c3d4e5f6',
    'maxmind-license-key': 'a1b2c3_a1b2c3d4e5a1b' '2c3d4e5f6a7b8c1d_mmk',
    'microsoft-teams-webhook': 'https://contoso0.webhook.office.com/webhookb2/a1b2c3d4-a1b2-c3d4-e5f6-a1b2c3d4e5f6@a1b2c3d4-a1b2-c3d4-' 'e5f6-a1b2c3d4e5f6/IncomingWebhook/a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4/a1b2c3d4-a1b2-c3d4-e5f6-a1b2c3d4e5f6',
    'mistral-api-key': 'mistral_api_key = a1b2c3d4e5a1b2c3d4e5' 'a1b2c3d4e5a1',
    'new-relic-browser-token': 'NRJS-a1b2c3d' '4e5f6a1b2c3d',
    'new-relic-insert-key': 'NRII-a1b2c3d4a1b2c' '3d4a1b2c3d4a1b2c3d4',
    'new-relic-user-key': 'NRAK-a1b2c3d4e5a' '1b2c3d4e5f6a7b8c',
    'notion-api-token': 'ntn_12345678901a1b2c3d4e5' 'a1b2c3d4e5a1b2c3d4e5f6a7b',
    'octopus-deploy-api-key': 'API-A1B2C3D4E5A' '1B2C3D4E5F6A7B8',
    'openrouter-api-key': 'sk-or-v1-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' 'c3d4e5f6a1b2',
    'openshift-user-token': 'sha256~a1b2c3d4e5a1b2c3d4' 'e5a1b2c3d4e5a1b2c3d4e5f6a',
    'perplexity-api-key': 'pplx-a1b2c3a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'plaid-access-token': 'access-sandbox-a1b2c3d4-a' '1b2-c3d4-e5f6-a1b2c3d4e5f6',
    'planetscale-api-token': 'pscale_tkn_a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3a1b2c3',
    'planetscale-oauth-token': 'pscale_oauth_a1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3a1b2c3',
    'planetscale-password': 'pscale_pw_a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3',
    'postman-api-key': 'PMAK-a1b2c3a1b2c3a1b2c3a1b2c3-a1' 'b2c3a1b2c3a1b2c3a1b2c3a1b2c3d4e5',
    'prefect-api-key': 'pnu_a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3',
    'pulumi-access-token': 'pul-a1b2c3a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3d4e5',
    'readme-api-token': 'rdme_a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3d4e5',
    'rubygems-api-key': 'rubygems_a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'scalingo-api-token': 'tk-us-a1b2c3a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'sendinblue-api-key': 'xkeysib-a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3' 'a1b2c3a1b2c3a1b2c3a1b2c3d4e5-a1b2c3d4e5f6a1b2',
    'sentry-org-token': 'sntrys_eyJpYXQiOa1b2c3d4e5LCJyZWdpb25fdXJsa1b2c3' 'd4e5_a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3d',
    'sentry-user-token': 'sntryu_a1b2c3a1b2c3a1b2c3a1b2c3a1b2' 'c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3d4e5',
    'settlemint-app-token': 'sm_aat_a1b2' 'c3d4e5f6a1b2',
    'settlemint-pat': 'sm_pat_a1b2' 'c3a1b2c3a1b2',
    'settlemint-sat': 'sm_sat_a1b2' 'c3a1b2c3a1b2',
    'shippo': 'shippo_test_a1b2c3a1b2c3a1' 'b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'shopify-access-token': 'shpat_a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1',
    'shopify-custom-access-token': 'shpca_a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1',
    'shopify-private-app-token': 'shppa_a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1',
    'shopify-shared-secret': 'shpss_a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1',
    'sidekiq-secret': 'BUNDLE_ENTERPRISE__CONTRIB' 'SYS__COM=a1b2c3d4:a1b2c3d4',
    'sidekiq-sensitive-url': 'https://a1b2c3d4:a1b2c3' 'd4@gems.contribsys.com/',
    'slack-app-token': 'xapp-1-A1B2C3D4E5F-1234567890123-a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2',
    'slack-config-access-token': 'xoxe.xoxp' '-1-' 'A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2' 'C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1',
    'slack-config-refresh-token': 'xoxe' '-1-' 'A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B' '2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1B2C3A1',
    'slack-legacy-token': 'xoxs-1234567890-1234567890-12345678' '90-a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1',
    'slack-legacy-workspace-token': 'xoxa-1-a1b2c3a1' 'b2c3a1b2c3a1b2c3',
    'snyk': 'SNYK_TOKEN=a1b2c3d4-a1b' '2-c3d4-a1b2-c3d4a1b2c3d4',
    'square-access-token': 'sq0atp-a1b2c3a' '1b2c3a1b2c3a1b2',
    'telegram-bot-token': '1234567890:Aa1b2c3a1b2c' '3a1b2c3a1b2c3a1b2c3a1b2',
    'together-api-key': 'together_api_key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' 'c3d4e5f6a1b2',
    'typeform-token': 'tfp_a1b2c3a1b2c3a1b2c3a1b2c3a1b' '2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c',
    'vault-batch-token': 'hvb.a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'vault-service-token': 'hvs.a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a' '1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3a1b2c3',
    'xai-api-key': 'xai-a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5' 'a1b2c3d4e5a1b2c3d4e5',
    # --- gitleaks port wave 2 ---
    'adafruit-api-key': 'adafruit_key = a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5f0',
    'airtable-api-key': 'airtable_api_key = a1b2' 'c3d4e5a1b2c3x',
    'algolia-api-key': 'algolia_api_key = a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5f0',
    'asana-client-id': 'asana_client_id = 12345' '67890123456',
    'asana-client-secret': 'asana_client_secret = a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5f0',
    'beamer-api-token': 'beamer_token = "b_a1b2c3d4e5f6a1b2c3d4e' '5f6a1b2c3d4e5f6a1b2c3d4"',
    'bitbucket-client-id': 'bitbucket_client_id = a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5f0',
    'bitbucket-client-secret': 'bitbucket_client_secret = a1b2c3d4e5a1b2c3d4e5a1b2c3d4e5a1b2c3' 'd4e5a1b2c3d4e5a1b2c3d4e5a1b2',
    'bittrex-access-key': 'bittrex_access_key = a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5f0',
    'codecov-access-token': 'codecov_token = a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5f0',
    'coinbase-access-token': 'coinbase_token = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f' '6a1b2c3d4e5f6a1b2c3d4e5f61234',
    'confluent-access-token': 'confluent_access_token = a1b' '2c3d4e5a1b2c3',
    'confluent-secret-key': 'confluent_secret_key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4' 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    'contentful-delivery-api-token': 'contentful_delivery_token = a1b2c3d4e5a1b2c3d4e5a1b' '2c3d4e5f0a1b2c3d4e5x',
    'datadog-access-token': 'datadog_api_key = a1b2c3d4e5a1b2c3d4e5a1b' '2c3d4e5a1b2c3d4e5',
    'discord-api-token': 'discord_token = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' 'c3d4e5f6a1b2c3d4e5f6a1b2',
    'dropbox-api-token': 'dropbox_token = a1b2c' '3d4e5f6a7b',
    'dropbox-long-lived-api-token': 'dropbox key = "a1b2c3d4e5fAAAAAAAAAA' 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d"',
    'dropbox-short-lived-api-token': 'dropbox_token = "sl.a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a' '1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b"',
    'droneci-access-token': 'droneci_token = a1b2c3d4e5f6a1b' '2c3d4e5f6a1b2c3d4',
    'fastly-api-token': 'fastly_api_key = a1b2c3d4e5f6a1b' '2c3d4e5f6a1b2c3d4',
    'finicity-client-secret': 'finicity_secret = a1b2c3' 'd4e5f6a1b2c3d4',
    'finnhub-access-token': 'finnhub_token = a1b2c3' 'd4e5f6a1b2c3d4',
    'flickr-access-token': 'flickr_token = a1b2c3d4e5f6a1b' '2c3d4e5f6a1b2c3d4',
    'freemius-secret-key': "'secret_key' => 'sk_a1b2c3a1b" "2c3a1b2c3a1b2c3a1b2x'",
    'freshbooks-access-token': 'freshbooks_token = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f' '6a1b2c3d4e5f6a1b2c3d4e5f61234',
    'gitter-access-token': 'gitter_token = a1b2c3d4e5f6a1b2c3d4' 'e5f6a1b2c3d4e5f6a1b2',
    'gocardless-api-token': 'gocardless_key = "live_a1b2c3a1b2a1b2c3a1b2' 'a1b2c3a1b2a1b2c3a1b2"',
    'heroku-api-key-legacy': 'heroku_key = "a1b2c3d4-a1b' '2-a1b2-a1b2-a1b2c3d4e5f6"',
    'hubspot-api-key': 'hubspot_key = "A1B2C3D4-A1B' '2-A1B2-A1B2-A1B2C3D4E5F6"',
    'intercom-api-key': 'intercom_api_key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f' '6a1b2c3d4e5f6a1b2c3d4e5f6',
    'jfrog-api-key': 'jfrog_api_key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4' 'e5f6a',
    'jfrog-identity-token': 'jfrog_token = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f' '6a1b2c3d4e5f6a1b2c3d4e5f61234',
    'kraken-access-token': 'kraken_api_key = a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2' 'c3d4e5f6a1b2c3d4',
    'kucoin-access-token': 'kucoin_key = "a1b2c3' 'd4a1b2c3d4a1b2c3d4"',
    'kucoin-secret-key': 'kucoin_secret = "a1b2c3d4-a1b2' '-c3d4-a1b2-c3d4a1b2c3d4"',
    'launchdarkly-access-token': 'launchdarkly_token = a1b2c3d4e5f6a1b2c3d4' 'e5f6a1b2c3d4e5f6a1b2',
    'lob-api-key': 'lob_key = "live_a1b2c3d4e5f6a1b' '2c3d4e5f6a1b2c3d4e5f"',
    'lob-pub-api-key': 'lob_pub = "test_pub_a1b2c3d4e5' 'f6a1b2c3d4e5f6a1b2c3d"',
    'mailchimp-api-key': 'mailchimp_api_key = "a1b2c3d4a1b2c3d4a1b2' 'c3d4a1b2c3d4-us12"',
    'mattermost-access-token': 'mattermost_token = "a1b2c3d4a1b2c3d4' 'a1b2c3d4a1"',
    'messagebird-api-token': 'messagebird_token = "a1b2c3d4a1b2c' '3d4a1b2c3d4a"',
    'messagebird-client-id': 'messagebird_client_id = "a1b2c3d4-a1b2' '-c3d4-a1b2-c3d4a1b2c3d4"',
    'netlify-access-token': 'netlify_token = "a1b2c3d4a1b2c3d4a1b2c3d4a1b' '2c3d4a1b2c3d4"',
    'sendbird-access-id': 'sendbird_access_id = "a1b2c3d4-a1b2' '-c3d4-a1b2-c3d4a1b2c3d4"',
    'sonar-api-token': 'sonar_token = "sqp_a1b2c3d4a1b2c3d4a1b2c3' 'd4a1b2c3d4a1b2c3d4"',
    'sourcegraph-access-token': 'sgp_a1b2c3d4e5f6a1b2_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4' 'e5f6a1b2c3d4',
    'squarespace-access-token': 'squarespace_token = "a1b2c3d4-a1b2' '-c3d4-a1b2-c3d4a1b2c3d4"',
    'travisci-access-token': 'travis_api_token = "a1b2c3d4e' '5f6a1b2c3d4e5"',
    'twitch-api-token': 'twitch_api_token = "a1b2c3d4e5f6a1b' '2c3d4e5f6a1b2c3"',
    'twitter-access-secret': 'twitter_access_secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4' 'e5f6a1b2c3d4e"',
    'twitter-access-token': 'twitter_access_token = "123456789012345' '-A1b2C3d4E5f6G7h8I9j0"',
    'twitter-api-key': 'twitter_api_key = "a1b2c3d4e5f6a' '1b2c3d4e5f6a"',
    'twitter-api-secret': 'twitter_api_secret = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f' '6a1b2c3d4e5f6a1"',
    'twitter-bearer-token': 'twitter_bearer_token = "AAAAAAAAAAAAAAAAAAAAAA' 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"',
    'yandex-api-key': 'yandex_api_key = "AQVNa1b2c3d4e5f6a1b' '2c3d4e5f6a1b2c3d4e5f"',
    'yandex-aws-access-token': 'yandex_aws_token = "YCa1b2c3d4e5f6a1b2c3d4e5' 'f6a1b2c3d4e5f6a1"',
    'yandex-oauth-access-token': 'yandex_token = "t1.A1b2C3d4E5.' + 'a1b2c3d4e5f6' * 7 + 'a1"',
}


@pytest.mark.parametrize("rule_id", sorted(FIXTURES))
def test_ported_rule_detects_its_fixture(rule_id: str) -> None:
    found = {f.rule for f in scan_text(FIXTURES[rule_id])}
    assert rule_id in found, (
        f"{rule_id} not reported for its fixture; got {sorted(found) or 'nothing'}"
    )


def test_every_rule_compiles_and_ids_are_unique() -> None:
    ids = [rule_id for rule_id, _display, _pattern in RULES]
    assert len(ids) == len(set(ids)), "duplicate rule ids in RULES"
    for rule_id, display, pattern in RULES:
        assert isinstance(pattern, re.Pattern), f"{rule_id}: pattern not compiled"
        assert rule_id and display


def test_rotation_guidance_present_or_cli_default_applies() -> None:
    from agentsweep.pipeline import _rotation_items

    # The CLI falls back to a generic message for rules without guidance,
    # so a missing entry degrades gracefully rather than crashing...
    found_by_file = {"f.jsonl": [(1, [], "v", SimpleNamespace(rule="no-such-rule"))]}
    assert _rotation_items(found_by_file) == [
        ("no-such-rule", "rotate via the issuing provider")
    ]

    # ...but every ported rule must ship provider-specific guidance,
    missing_ported = sorted(r for r in FIXTURES if r not in ROTATION_GUIDANCE)
    assert not missing_ported, f"ported rules lacking guidance: {missing_ported}"

    # and right now every shipped rule and detector has an explicit entry.
    from agentsweep.scanner import DETECTOR_IDS
    rule_ids = {rule_id for rule_id, _d, _p in RULES} | set(DETECTOR_IDS)
    missing = sorted(rule_ids - set(ROTATION_GUIDANCE))
    assert not missing, f"rules lacking guidance: {missing}"
    stale = sorted(set(ROTATION_GUIDANCE) - rule_ids)
    assert not stale, f"guidance for rules that no longer exist: {stale}"


# Discord bot tokens are a native rule (no gitleaks equivalent), so they live
# here as dedicated cases rather than in FIXTURES. Tokens are split across
# adjacent string literals so this file never holds a contiguous token-shaped
# string (push-protection hygiene, same as FIXTURES).
_DISCORD_CLASSIC = "NzkyNzE1NDU0MTk2MDg4ODQy" ".X-hvzA." "Ovy4MCQywSkoMRRclStW4xAYK7I"
_DISCORD_NEW = "MTk4NjIyNDgzNDcxOTI1MjQ4" ".GhAbCd." "7y8aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678"


@pytest.mark.parametrize("token", [_DISCORD_CLASSIC, _DISCORD_NEW])
def test_discord_bot_token_detected(token: str) -> None:
    assert any(f.rule == "discord-bot-token" for f in scan_text(token)), (
        f"discord-bot-token not reported for {token!r}"
    )
    # ...and when embedded in a realistic env assignment with quotes.
    assert any(
        f.rule == "discord-bot-token"
        for f in scan_text(f'DISCORD_TOKEN="{token}"')
    )


@pytest.mark.parametrize("text", [
    # A JWT shares the dotted shape but starts with eyJ, never M/N/O.
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKLmnoPQRstuvWXYz12",
    # 40-char git SHA: no dots, no [MNO]-anchored base64 triple.
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    # Final segment too short to be a real bot token.
    "NzkyNzE1NDU0MTk2MDg4ODQy" ".X-hvzA." "tooShort123",
])
def test_discord_bot_token_no_false_positive(text: str) -> None:
    assert not any(f.rule == "discord-bot-token" for f in scan_text(text))


def test_discord_keyword_hex_stays_api_token() -> None:
    # The legacy keyword+64-hex rule (discord-api-token) must keep owning this
    # shape; the new dotted bot-token rule must not fire on it.
    hit = "discord_token = " + "0123456789abcdef" * 4
    rules = {f.rule for f in scan_text(hit)}
    assert "discord-api-token" in rules
    assert "discord-bot-token" not in rules


# Discord webhook URLs are also native (no gitleaks rule). The token segment is
# split across literals so this file never holds a contiguous webhook string.
_WEBHOOK_TOKEN = ("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
                  "AbCdEfGhIjKlMnOpQrStUvWx")  # 60 base64url chars


@pytest.mark.parametrize("host", ["discord.com", "discordapp.com"])
def test_discord_webhook_detected(host: str) -> None:
    url = f"https://{host}/api/webhooks/" "123456789012345678/" + _WEBHOOK_TOKEN
    assert any(f.rule == "discord-webhook" for f in scan_text(url)), (
        f"discord-webhook not reported for {host}"
    )


@pytest.mark.parametrize("text", [
    # A normal Discord channel link is not a webhook with a token.
    "see https://discord.com/channels/123456789012345678/987654321098765432",
    # Webhook path but the token is far too short.
    "https://discord.com/api/webhooks/123456789012345678/short",
])
def test_discord_webhook_no_false_positive(text: str) -> None:
    assert not any(f.rule == "discord-webhook" for f in scan_text(text))
