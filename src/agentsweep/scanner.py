from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    rule: str
    display: str
    value: str
    masked: str
    span: tuple[int, int]
    file: Path | None = None
    line: int | None = None
    keypath: list = field(default_factory=list)


RULES: list[tuple[str, str, re.Pattern]] = [
    ("aws-access-key", "AWS access key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-session-token", "AWS session token",
        re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("github-pat", "GitHub PAT",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-oauth", "GitHub OAuth token",
        re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github-app", "GitHub App token",
        re.compile(r"\b(?:ghs|ghu)_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained", "GitHub fine-grained PAT",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("stripe-live", "Stripe live secret key",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b")),
    ("stripe-test", "Stripe test secret key",
        re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{24,}\b")),
    ("openai", "OpenAI API key",
        # (?!ant-) / (?!or-v1-) keep this broad rule from shadowing Anthropic
        # and OpenRouter keys, which would otherwise tie on span and win the
        # overlap dedupe by list order.
        re.compile(r"\bsk-(?!ant-)(?!or-v1-)(?:proj-)?[A-Za-z0-9_-]{40,}\b")),
    ("anthropic", "Anthropic API key",
        re.compile(r"\bsk-ant-(?:api|sid)[0-9]*-[A-Za-z0-9_-]{32,}\b")),
    ("google-api", "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("google-oauth-client-secret", "Google OAuth client secret",
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b")),
    ("google-service-account-key", "Google service-account key",
        # Anchored on the JSON "type": "service_account" marker and confirmed
        # by a nearby private_key_id, so a bare PEM block (already caught by
        # private-key-pem) doesn't also trip this rule.
        re.compile(r'"type":\s*"service_account"[\s\S]{0,200}?"private_key_id":\s*"[a-f0-9]{40}"')),
    ("slack-bot", "Slack bot token",
        re.compile(r"\bxoxb-[A-Za-z0-9-]{10,}\b")),
    ("slack-user", "Slack user token",
        re.compile(r"\bxoxp-[A-Za-z0-9-]{10,}\b")),
    ("slack-webhook", "Slack webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("huggingface", "Hugging Face token",
        re.compile(r"\bhf_[A-Za-z0-9]{34}\b")),
    ("jwt", "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private-key-pem", "Private key (PEM block)",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
                   r"[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("db-url-with-password", "Database URL with password",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                   r"[^:/\s]+:[^@\s'\"]+@[^\s'\"/]+")),
    ("npm-token", "npm access token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", "PyPI upload token",
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")),
    ("sendgrid", "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("twilio", "Twilio API key",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("discord-bot-token", "Discord bot token",
        # id.timestamp.hmac in base64url. The first segment is base64 of the
        # bot's snowflake (a decimal id), so it always begins M/N/O — that
        # anchor keeps this off JWTs (eyJ…) and other dotted tokens. No
        # keyword literal anywhere → the prefilter extractor returns () and
        # the rule always runs.
        re.compile(r"\b[MNO][\w-]{23,27}\.[\w-]{6,7}\.[\w-]{27,40}(?![\w-])")),
    ("discord-webhook", "Discord webhook URL",
        # discord.com / discordapp.com /api/webhooks/<17-20 digit id>/<token>.
        # Anchored on the "discord" literal so the prefilter scopes it tightly;
        # every quantifier is bounded.
        re.compile(r"\bdiscord(?:app)?\.com/api/webhooks/\d{17,20}/[\w-]{60,80}\b")),
    # --- ported from gitleaks (see scripts/rules_drift.py mapping) ---
    ('1password-secret-key', '1Password secret key',
        re.compile('\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b')),
    ('1password-service-account-token', '1Password service account token',
        re.compile('\\bops_eyJ[a-zA-Z0-9+/]{250,}={0,3}')),
    ('adobe-client-secret', 'Adobe client secret',
        re.compile('\\bp8e-[a-zA-Z0-9]{32}\\b')),
    ('age-secret-key', 'age encryption secret key',
        re.compile('\\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\\b')),
    ('airtable-pat', 'Airtable personal access token',
        re.compile('\\bpat[A-Za-z0-9]{14}\\.[a-f0-9]{64}\\b')),
    ('alibaba-access-key-id', 'Alibaba Cloud AccessKey ID',
        re.compile('\\bLTAI[a-zA-Z0-9]{20}\\b')),
    ('anthropic-admin-key', 'Anthropic admin API key',
        re.compile('\\bsk-ant-admin01-[A-Za-z0-9_-]{93}AA\\b')),
    ('artifactory-api-key', 'Artifactory API key',
        re.compile('\\bAKCp[A-Za-z0-9]{69}\\b')),
    ('artifactory-reference-token', 'Artifactory reference token',
        re.compile('\\bcmVmd[A-Za-z0-9]{59}\\b')),
    ('atlassian-api-token', 'Atlassian API token',
        re.compile('\\bATATT3[A-Za-z0-9_=-]{186}(?![A-Za-z0-9_=-])')),
    ('authress-service-client-key', 'Authress service client access key',
        re.compile('\\b(?:sc|ext|scauth|authress)_[a-zA-Z0-9]{5,30}\\.[a-zA-Z0-9]{4,6}\\.acc[_-][a-zA-Z0-9-]{10,32}\\.[a-zA-Z0-9+/_=-]{30,120}(?![a-zA-Z0-9+/_=-])')),
    ('aws-bedrock-api-key-long-lived', 'AWS Bedrock API key (long-lived)',
        re.compile('\\bABSK[A-Za-z0-9+/]{109,269}={0,2}(?![A-Za-z0-9+/=])')),
    ('aws-bedrock-api-key-short-lived', 'AWS Bedrock API key (short-lived)',
        re.compile('\\bbedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t')),
    ('azure-ad-client-secret', 'Azure AD client secret',
        re.compile('(?<![a-zA-Z0-9_~.])[a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34}(?![a-zA-Z0-9_~.-])')),
    ('clickhouse-cloud-api-secret', 'ClickHouse Cloud API secret key',
        re.compile('\\b4b1d[A-Za-z0-9]{38}\\b')),
    ('clojars-api-token', 'Clojars API token',
        re.compile('(?i)\\bCLOJARS_[a-z0-9]{60}\\b')),
    ('cloudflare-origin-ca-key', 'Cloudflare Origin CA key',
        re.compile('\\bv1\\.0-[a-f0-9]{24}-[a-f0-9]{146}\\b')),
    ('cohere-api-key', 'Cohere API key',
        re.compile('(?i)[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    # Gap between "curl" and the auth flag is bounded: gitleaks runs these on
    # RE2 (linear-time); Python's backtracking engine goes quadratic on
    # unbounded .* when a line mentions curl many times.
    ('curl-auth-header', 'curl Authorization header',
        re.compile('\\bcurl\\b(?:.{0,200}?|.{0,200}?(?:[\\r\\n]{1,2}.{0,200}?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:"(?i:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))"|\'(?i:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\')(?:\\B|\\s|\\Z)')),
    ('curl-auth-user', 'curl basic auth credentials',
        re.compile('\\bcurl\\b(?:.{0,200}?|.{0,200}?(?:[\\r\\n]{1,2}.{0,200}?){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|\'([^:\']{3,}:[^\']{3,})\'|((?:"[^"]{3,}"|\'[^\']{3,}\'|[\\w$@.-]+):(?:"[^"]{3,}"|\'[^\']{3,}\'|[\\w${}@.-]+)))(?=\\s|\\Z)')),
    ('databricks-api-token', 'Databricks API token',
        re.compile('\\bdapi[a-f0-9]{32}(?:-\\d)?\\b')),
    ('deepseek-api-key', 'DeepSeek API key',
        re.compile('(?i)[\\w.-]{0,50}?(?:deepseek)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(sk-[a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('defined-networking-api-token', 'Defined Networking API token',
        re.compile('(?i)\\bdnkey-[a-z0-9=_-]{26}-[a-z0-9=_-]{52}(?=[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('digitalocean-access-token', 'DigitalOcean OAuth access token',
        re.compile('\\bdoo_v1_[a-f0-9]{64}\\b')),
    ('digitalocean-pat', 'DigitalOcean personal access token',
        re.compile('\\bdop_v1_[a-f0-9]{64}\\b')),
    ('digitalocean-refresh-token', 'DigitalOcean OAuth refresh token',
        re.compile('(?i)\\bdor_v1_[a-f0-9]{64}\\b')),
    ('doppler-api-token', 'Doppler API token',
        re.compile('\\bdp\\.pt\\.(?i:[a-z0-9]{43})\\b')),
    ('duffel-api-token', 'Duffel API token',
        re.compile('\\bduffel_(?:test|live)_(?i:[a-z0-9_=-]{43})')),
    ('dynatrace-api-token', 'Dynatrace API token',
        re.compile('\\bdt0c01\\.(?i:[a-z0-9]{24}\\.[a-z0-9]{64})\\b')),
    ('easypost-api-token', 'EasyPost API token',
        re.compile('\\bEZAK(?i:[a-z0-9]{54})\\b')),
    ('easypost-test-api-token', 'EasyPost test API token',
        re.compile('\\bEZTK(?i:[a-z0-9]{54})\\b')),
    # gitleaks' facebook-access-token (digits|secret) is omitted: upstream
    # relies on an entropy gate to stay precise; without one it matches any
    # pipe-delimited log line with a microsecond timestamp.
    ('facebook-page-token', 'Facebook page access token',
        re.compile('\\bEAA[MC][A-Za-z0-9]{100,}\\b')),
    ('fireworks-api-key', 'Fireworks AI API key',
        re.compile('(?i)[\\w.-]{0,50}?(?:fireworks)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(fw_[A-Za-z0-9]{20,24})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('flutterwave-encryption-key', 'Flutterwave encryption key',
        re.compile('\\bFLWSECK_TEST-(?i:[a-h0-9]{12})\\b')),
    ('flutterwave-public-key', 'Flutterwave public key',
        re.compile('\\bFLWPUBK_TEST-(?i:[a-h0-9]{32}-x)\\b')),
    ('flutterwave-secret-key', 'Flutterwave secret key',
        re.compile('\\bFLWSECK_TEST-(?i:[a-h0-9]{32}-x)\\b')),
    ('flyio-token', 'Fly.io access token',
        re.compile('\\b(?:fo1_[\\w-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}|fm2_[A-Za-z0-9+/]{100,}={0,3})(?![\\w+/=-])')),
    ('frameio-token', 'Frame.io API token',
        re.compile('\\bfio-u-[A-Za-z0-9_=-]{64}(?![\\w=-])')),
    ('github-refresh-token', 'GitHub refresh token',
        re.compile('\\bghr_[A-Za-z0-9]{36}\\b')),
    ('gitlab-cicd-job-token', 'GitLab CI/CD job token',
        re.compile('\\bglcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}(?![\\w-])')),
    ('gitlab-deploy-token', 'GitLab deploy token',
        re.compile('\\bgldt-[0-9a-zA-Z_-]{20}(?![\\w-])')),
    ('gitlab-feature-flag-client-token', 'GitLab feature flag client token',
        re.compile('\\bglffct-[0-9a-zA-Z_-]{20}(?![\\w-])')),
    ('gitlab-feed-token', 'GitLab feed token',
        re.compile('\\bglft-[0-9a-zA-Z_-]{20}(?![\\w-])')),
    ('gitlab-incoming-mail-token', 'GitLab incoming mail token',
        re.compile('\\bglimt-[0-9a-zA-Z_-]{25}(?![\\w-])')),
    ('gitlab-kubernetes-agent-token', 'GitLab Kubernetes agent token',
        re.compile('\\bglagent-[0-9a-zA-Z_-]{50}(?![\\w-])')),
    ('gitlab-oauth-app-secret', 'GitLab OAuth application secret',
        re.compile('\\bgloas-[0-9a-zA-Z_-]{64}(?![\\w-])')),
    ('gitlab-pat', 'GitLab personal access token',
        re.compile('\\bglpat-[\\w-]{20}(?![\\w-])')),
    ('gitlab-pat-routable', 'GitLab personal access token (routable)',
        re.compile('\\bglpat-[0-9A-Za-z_-]{27,300}\\.[0-9a-z]{9}\\b')),
    ('gitlab-pipeline-trigger', 'GitLab pipeline trigger token',
        re.compile('\\bglptt-[0-9a-f]{40}\\b')),
    ('gitlab-runner-registration', 'GitLab runner registration token',
        re.compile('\\bGR1348941[0-9A-Za-z_-]{20}\\b')),
    ('gitlab-runner-auth', 'GitLab runner authentication token',
        re.compile('\\bglrt-[0-9A-Za-z_-]{20}\\b')),
    ('gitlab-runner-auth-routable', 'GitLab runner authentication token (routable)',
        re.compile('\\bglrt-t\\d_[0-9A-Za-z_-]{27,300}\\.[0-9a-z]{9}\\b')),
    ('gitlab-scim', 'GitLab SCIM token',
        re.compile('\\bglsoat-[0-9A-Za-z_-]{20}\\b')),
    ('gitlab-session-cookie', 'GitLab session cookie',
        re.compile('\\b_gitlab_session=[0-9a-z]{32}\\b')),
    ('grafana-api-key', 'Grafana API key',
        re.compile('\\beyJrIjoi[A-Za-z0-9]{70,400}={0,3}')),
    ('grafana-cloud-token', 'Grafana Cloud API token',
        re.compile('\\bglc_[A-Za-z0-9+/]{32,400}={0,3}')),
    ('grafana-service-account', 'Grafana service account token',
        re.compile('\\bglsa_[A-Za-z0-9]{32}_[0-9a-fA-F]{8}\\b')),
    ('groq-api-key', 'Groq API key',
        re.compile('\\bgsk_[A-Za-z0-9]{52}\\b')),
    ('harness', 'Harness access token (PAT/SAT)',
        re.compile('\\b(?:pat|sat)\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9]{24}\\.[A-Za-z0-9]{20}\\b')),
    ('terraform-api-token', 'HashiCorp Terraform Cloud API token',
        re.compile('\\b[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_=-]{60,70}\\b')),
    ('heroku-api-key', 'Heroku API key',
        re.compile('\\bHRKU-AA[0-9A-Za-z_-]{58}\\b')),
    ('huggingface-org', 'Hugging Face organization API token',
        re.compile('\\bapi_org_[A-Za-z]{34}\\b')),
    ('infracost', 'Infracost API token',
        re.compile('\\bico-[A-Za-z0-9]{32}\\b')),
    ('intra42-client-secret', 'Intra42 client secret',
        re.compile('\\bs-s4t2(?:ud|af)-[a-fA-F0-9]{64}\\b')),
    ('jwt-base64', 'JSON Web Token (base64-encoded)',
        re.compile('\\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}')),
    ('linear-api-key', 'Linear API key',
        re.compile('\\blin_api_[A-Za-z0-9]{40}\\b')),
    ('mailgun-private-token', 'Mailgun private API token',
        re.compile('(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('mailgun-public-key', 'Mailgun public validation key',
        re.compile('(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('mailgun-signing-key', 'Mailgun webhook signing key',
        re.compile('(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('mapbox-api-token', 'Mapbox API token',
        re.compile('\\bpk\\.[a-zA-Z0-9]{60}\\.[a-zA-Z0-9]{22}\\b')),
    ('maxmind-license-key', 'MaxMind license key',
        re.compile('\\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk\\b')),
    ('microsoft-teams-webhook', 'Microsoft Teams incoming webhook URL',
        re.compile('https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}')),
    ('mistral-api-key', 'Mistral AI API key',
        re.compile('(?i)[\\w.-]{0,50}?(?:mistral)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([A-Za-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('new-relic-browser-token', 'New Relic ingest browser API token',
        re.compile('\\bNRJS-[a-fA-F0-9]{19}\\b')),
    ('new-relic-insert-key', 'New Relic insights insert key',
        re.compile('\\bNRII-[A-Za-z0-9-]{32}\\b')),
    ('new-relic-user-key', 'New Relic user API key',
        re.compile('\\bNRAK-[A-Za-z0-9]{27}\\b')),
    ('notion-api-token', 'Notion API token',
        re.compile('\\bntn_[0-9]{11}[A-Za-z0-9]{35}\\b')),
    # Digit lookahead stands in for gitleaks' entropy gate: real keys are
    # random base32-ish; SCREAMING_CASE words like API-TIMEOUTBUDGETEXCEEDED
    # contain no digits.
    ('octopus-deploy-api-key', 'Octopus Deploy API key',
        re.compile('\\bAPI-(?=[A-Z0-9]*[0-9])[A-Z0-9]{26}\\b')),
    ('openrouter-api-key', 'OpenRouter API key',
        re.compile('\\bsk-or-v1-[0-9a-f]{64}\\b')),
    ('openshift-user-token', 'OpenShift user token',
        re.compile('\\bsha256~[\\w-]{43}(?![\\w-])')),
    ('perplexity-api-key', 'Perplexity API key',
        re.compile('\\bpplx-[A-Za-z0-9]{48}\\b')),
    ('plaid-access-token', 'Plaid access token',
        re.compile('\\baccess-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b')),
    ('planetscale-api-token', 'PlanetScale API token',
        re.compile('\\bpscale_tkn_[\\w=.\\-]{32,64}(?![\\w=.\\-])')),
    ('planetscale-oauth-token', 'PlanetScale OAuth token',
        re.compile('\\bpscale_oauth_[\\w=.\\-]{32,64}(?![\\w=.\\-])')),
    ('planetscale-password', 'PlanetScale database password',
        re.compile('\\bpscale_pw_[\\w=.\\-]{32,64}(?![\\w=.\\-])')),
    ('postman-api-key', 'Postman API key',
        re.compile('\\bPMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}\\b')),
    ('prefect-api-key', 'Prefect API key',
        re.compile('\\bpnu_[A-Za-z0-9]{36}\\b')),
    ('pulumi-access-token', 'Pulumi access token',
        re.compile('\\bpul-[a-f0-9]{40}\\b')),
    ('readme-api-token', 'ReadMe API token',
        re.compile('\\brdme_[a-z0-9]{70}\\b')),
    ('rubygems-api-key', 'RubyGems API key',
        re.compile('\\brubygems_[a-f0-9]{48}\\b')),
    ('scalingo-api-token', 'Scalingo API token',
        re.compile('\\btk-us-[\\w-]{48}(?![\\w-])')),
    ('sendinblue-api-key', 'Sendinblue (Brevo) API key',
        re.compile('\\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\\b')),
    ('sentry-org-token', 'Sentry organization auth token',
        re.compile('\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?![a-zA-Z0-9+/])')),
    ('sentry-user-token', 'Sentry user auth token',
        re.compile('\\bsntryu_[a-f0-9]{64}\\b')),
    ('settlemint-app-token', 'SettleMint application access token',
        re.compile('\\bsm_aat_[A-Za-z0-9]{16}\\b')),
    ('settlemint-pat', 'SettleMint personal access token',
        re.compile('\\bsm_pat_[A-Za-z0-9]{16}\\b')),
    ('settlemint-sat', 'SettleMint service access token',
        re.compile('\\bsm_sat_[A-Za-z0-9]{16}\\b')),
    ('shippo', 'Shippo API token',
        re.compile('\\bshippo_(?:live|test)_[a-fA-F0-9]{40}\\b')),
    ('shopify-access-token', 'Shopify access token',
        re.compile('\\bshpat_[a-fA-F0-9]{32}\\b')),
    ('shopify-custom-access-token', 'Shopify custom app access token',
        re.compile('\\bshpca_[a-fA-F0-9]{32}\\b')),
    ('shopify-private-app-token', 'Shopify private app access token',
        re.compile('\\bshppa_[a-fA-F0-9]{32}\\b')),
    ('shopify-shared-secret', 'Shopify shared secret',
        re.compile('\\bshpss_[a-fA-F0-9]{32}\\b')),
    ('sidekiq-secret', 'Sidekiq Enterprise credential',
        re.compile('(?i)[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}[a-f0-9]{8}:[a-f0-9]{8}(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('sidekiq-sensitive-url', 'Sidekiq Enterprise gem URL with credentials',
        re.compile('(?i)\\bhttps?://[a-f0-9]{8}:[a-f0-9]{8}@(?:gems|enterprise)\\.contribsys\\.com\\b')),
    ('slack-app-token', 'Slack app-level token',
        re.compile('(?i)\\bxapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+\\b')),
    ('slack-config-access-token', 'Slack configuration access token',
        re.compile('(?i)\\bxoxe\\.xox[bp]-\\d-[A-Z0-9]{163,166}\\b')),
    ('slack-config-refresh-token', 'Slack configuration refresh token',
        re.compile('(?i)\\bxoxe-\\d-[A-Z0-9]{146}\\b')),
    ('slack-legacy-token', 'Slack legacy token',
        re.compile('\\bxox[os]-\\d+-\\d+-\\d+-[a-fA-F0-9]+\\b')),
    ('slack-legacy-workspace-token', 'Slack legacy workspace token',
        re.compile('\\bxox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}\\b')),
    ('snyk', 'Snyk API token',
        re.compile('(?i)[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    # EAAA branch requires a digit and a lowercase char (gitleaks uses an
    # entropy gate): base64 of zero-padded binary encodes to 'EAAAAA...'.
    ('square-access-token', 'Square access token',
        re.compile('\\b(?:EAAA(?=[\\w-]{0,60}[0-9])(?=[\\w-]{0,60}[a-z])|sq0atp-)'
                   '[\\w-]{22,60}(?![\\w-])')),
    ('telegram-bot-token', 'Telegram bot token',
        re.compile('\\b\\d{5,16}:A[A-Za-z0-9_-]{34}(?![A-Za-z0-9_-])')),
    ('together-api-key', 'Together AI API key',
        re.compile('(?i)[\\w.-]{0,50}?(?:together)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('typeform-token', 'Typeform API token',
        re.compile('\\btfp_[A-Za-z0-9_.=-]{59}(?![A-Za-z0-9_.=-])')),
    ('vault-batch-token', 'HashiCorp Vault batch token',
        re.compile('\\bhvb\\.[\\w-]{138,300}(?![\\w-])')),
    # Legacy 's.<24>' branch dropped (gitleaks keeps it behind an entropy
    # gate): it matches any single-letter variable followed by a 24-char
    # method/attribute name. hvs. covers every token since Vault 1.10.
    ('vault-service-token', 'HashiCorp Vault service token',
        re.compile('\\bhvs\\.[\\w-]{90,120}(?![\\w-])')),
    ('xai-api-key', 'xAI (Grok) API key',
        re.compile('\\bxai-[0-9a-zA-Z_]{80}\\b')),

    # --- gitleaks port wave 2 ---
    ('adafruit-api-key', 'Adafruit API Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9_-]*[0-9])(?=[a-z0-9_-]*[a-z])([a-z0-9_-]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('airtable-api-key', 'Airtable API Key (Legacy)',
        re.compile('(?i)[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{17})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('algolia-api-key', 'Algolia API Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('asana-client-id', 'Asana Client ID',
        re.compile('(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9]{16})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('asana-client-secret', 'Asana Client Secret',
        re.compile('(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('beamer-api-token', 'Beamer API Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('bitbucket-client-id', 'Bitbucket Client ID',
        re.compile('(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('bitbucket-client-secret', 'Bitbucket Client Secret',
        re.compile('(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9=_-]*[0-9])(?=[a-z0-9=_-]*[a-z])([a-z0-9=_-]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('bittrex-access-key', 'Bittrex Access Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('codecov-access-token', 'Codecov Access Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('coinbase-access-token', 'Coinbase Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:coinbase)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9_-]*[0-9])(?=[a-z0-9_-]*[a-z])([a-z0-9_-]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('confluent-access-token', 'Confluent Access Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{16})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('confluent-secret-key', 'Confluent Secret Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('contentful-delivery-api-token', 'Contentful Delivery API Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9=_-]*[0-9])(?=[a-z0-9=_-]*[a-z])([a-z0-9=_-]{43})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('datadog-access-token', 'Datadog Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:datadog)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('discord-api-token', 'Discord API Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:discord)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('dropbox-api-token', 'Dropbox API Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:dropbox)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{15})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('dropbox-long-lived-api-token', 'Dropbox Long-Lived API Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{11}AAAAAAAAAA[a-z0-9\\-_=]{43})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('dropbox-short-lived-api-token', 'Dropbox Short-Lived API Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('droneci-access-token', 'Drone CI Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:droneci)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('fastly-api-token', 'Fastly API Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:fastly)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9=_\\-]*[0-9])(?=[a-z0-9=_\\-]*[a-z])([a-z0-9=_\\-]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('finicity-client-secret', 'Finicity Client Secret',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:finicity)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{20})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('finnhub-access-token', 'Finnhub Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:finnhub)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{20})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('flickr-access-token', 'Flickr Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:flickr)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{32})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('freemius-secret-key', 'Freemius Secret Key',
        re.compile('["\']secret_key["\']\\s*=>\\s*["\'](sk_[\\S]{29})["\']')),
    ('freshbooks-access-token', 'FreshBooks Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:freshbooks)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('gitter-access-token', 'Gitter Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:gitter)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9_-]*[0-9])(?=[a-z0-9_-]*[a-z])([a-z0-9_-]{40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('gocardless-api-token', 'GoCardless API Token',
        re.compile('(?i)[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(live_[a-zA-Z0-9\\-_=]{40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('heroku-api-key-legacy', 'Heroku API Key (UUID format)',
        re.compile('(?i)[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('hubspot-api-key', 'HubSpot API Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('intercom-api-key', 'Intercom API Key',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:intercom)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9=_\\-]*[0-9])(?=[a-z0-9=_\\-]*[a-z])([a-z0-9=_\\-]{60})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('jfrog-api-key', 'JFrog API Key',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{73})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('jfrog-identity-token', 'JFrog Identity Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9]*[0-9])(?=[a-z0-9]*[a-z])([a-z0-9]{64})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('kraken-access-token', 'Kraken Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:kraken)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9/=_+\\-]*[0-9])(?=[a-z0-9/=_+\\-]*[a-z])([a-z0-9/=_+\\-]{80,90})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('kucoin-access-token', 'KuCoin Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:kucoin)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('kucoin-secret-key', 'KuCoin Secret Key',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:kucoin)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('launchdarkly-access-token', 'LaunchDarkly Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(?=[a-z0-9=_\\-]*[0-9])(?=[a-z0-9=_\\-]*[a-z])([a-z0-9=_\\-]{40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('lob-api-key', 'Lob API Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('lob-pub-api-key', 'Lob Publishable API Key',
        re.compile('(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('mailchimp-api-key', 'Mailchimp API Key',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:MailchimpSDK\\.initialize|mailchimp)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('mattermost-access-token', 'Mattermost Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:mattermost)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('messagebird-api-token', 'MessageBird API Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:message[_\\-]?bird)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('messagebird-client-id', 'MessageBird Client ID',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:message[_\\-]?bird)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('netlify-access-token', 'Netlify Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:netlify)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('sendbird-access-id', 'Sendbird Access ID',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:sendbird)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('sonar-api-token', 'SonarQube/SonarCloud API Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:sonar[_.\\-]?(?:login|token))(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('sourcegraph-access-token', 'Sourcegraph Access Token',
        re.compile('(?:sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})')),
    ('squarespace-access-token', 'Squarespace Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?(?:squarespace)(?:[ \\t\\w.\\-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('travisci-access-token', 'Travis CI Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?travis[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('twitch-api-token', 'Twitch API Token',
        re.compile('(?i)[\\w.\\-]{0,50}?twitch[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('twitter-access-secret', 'Twitter/X Access Token Secret',
        re.compile('(?i)[\\w.\\-]{0,50}?twitter[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('twitter-access-token', 'Twitter/X Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?twitter[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('twitter-api-key', 'Twitter/X API Key',
        re.compile('(?i)[\\w.\\-]{0,50}?twitter[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('twitter-api-secret', 'Twitter/X API Secret',
        re.compile('(?i)[\\w.\\-]{0,50}?twitter[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('twitter-bearer-token', 'Twitter/X Bearer Token',
        re.compile('(?i)[\\w.\\-]{0,50}?twitter[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('yandex-api-key', 'Yandex API Key',
        re.compile('(?i)[\\w.\\-]{0,50}?yandex[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('yandex-aws-access-token', 'Yandex Cloud AWS Access Key',
        re.compile('(?i)[\\w.\\-]{0,50}?yandex[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
    ('yandex-oauth-access-token', 'Yandex OAuth Access Token',
        re.compile('(?i)[\\w.\\-]{0,50}?yandex[\\w.\\- \\t]{0,20}[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}(t1\\.[A-Za-z0-9_\\-]{1,100}={0,2}\\.[A-Za-z0-9_\\-]{86}={0,2})(?:[\\x60\'"\\s;]|\\\\[nr]|$)')),
]


def mask(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:3] + "*" * max(0, len(secret) - 3)
    return secret[:6] + "*" * 8 + secret[-4:]


# Keyword pre-filter (the trick gitleaks' engine uses): many ported rules
# are "context" rules — a lazy [\w.-]{0,50}? gap, then a mandatory provider
# keyword, then the value. That leading gap makes the engine retry at every
# position of a long string, so 50 such rules turn an 80KB paste into a
# multi-second scan. Each rule's keyword is *mandatory* (every string the
# rule can match contains it), so we skip the regex entirely when none of
# the keyword's literals appear — provably lossless, and the per-rule
# fixture tests fail loudly if a prefilter ever over-skips.
# The lazy provider-context gap, e.g. `[\w.-]{0,50}?`. What follows it is
# the mandatory keyword — either a `(?:a|b)` group or a bare literal.
_GAP_SIG = re.compile(r"\{0,\d+\}\?")


_LIT_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-:/@~=")
_FLAG_GROUP = re.compile(r"^\(\?[aiLmsux]+\)")
_SCOPED_FLAG = re.compile(r"^\(\?[aiLmsux]+:")


def _prefilter_literals(pattern: str) -> tuple[str, ...]:
    """A required-substring set for a rule: a match implies at least one is
    present, so the regex can be skipped when none appear. Context rules
    use the keyword after the lazy gap; everything else uses the literal
    the pattern is anchored on. Returns () (always run) when nothing safe
    can be extracted. Losslessness is enforced by the per-rule fixture
    tests — a wrong literal makes that rule's fixture undetectable."""
    ctx = _context_literals(pattern)
    if ctx:
        return ctx
    return _leading_literals(pattern)


def _context_literals(pattern: str) -> tuple[str, ...]:
    m = _GAP_SIG.search(pattern)
    if not m:
        return ()
    rest = pattern[m.end():]
    if rest[:3] == "(?:" or (rest[:1] == "(" and rest[:2] != "(?"):
        body, _ = _read_group(rest, 0)
        return _alts_to_literals(body) if body is not None else ()
    lit = _literal_run(rest)
    return (lit.lower(),) if len(lit) >= 3 else ()


def _leading_literals(pattern: str) -> tuple[str, ...]:
    """Literal(s) the pattern must start with, after stripping flags/anchors."""
    s = _FLAG_GROUP.sub("", pattern, count=1)
    while True:
        if s[:2] in ("\\b", "\\B", "\\A"):
            s = s[2:]
            continue
        if s[:1] == "^":
            s = s[1:]
            continue
        sm = _SCOPED_FLAG.match(s)
        if sm:
            s = s[sm.end():]
            continue
        break
    if s[:3] == "(?:" or (s[:1] == "(" and s[:2] != "(?"):
        body, _ = _read_group(s, 0)
        return _alts_to_literals(body) if body is not None else ()
    lit = _literal_run(s)
    return (lit.lower(),) if len(lit) >= 3 else ()


def _alts_to_literals(body: str) -> tuple[str, ...]:
    lits: list[str] = []
    for alt in _split_top_level(body):
        lit = _literal_run(alt)
        if len(lit) < 3:
            return ()  # an alternative has no safe anchor — don't prefilter
        lits.append(lit.lower())
    return tuple(dict.fromkeys(lits))


def _literal_run(s: str) -> str:
    """Leading run of guaranteed-literal characters (escapes like \\. count)."""
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            nxt = s[i + 1] if i + 1 < len(s) else ""
            if nxt and nxt in ".-_/+*?()[]{}|^$@~=":
                out.append(nxt)
                i += 2
                continue
            break  # \d \w \s \b ... — not a literal
        if c in _LIT_CHARS:
            out.append(c)
            i += 1
            continue
        break
    return "".join(out)


def _read_group(s: str, open_idx: int) -> tuple[str | None, int]:
    """Body and end index of the (...) group starting at s[open_idx] == '('."""
    i = open_idx + 1
    if s[i:i + 2] == "?:":
        i += 2
    depth = 1
    body: list[str] = []
    while i < len(s):
        c = s[i]
        if c == "\\":
            body.append(s[i:i + 2])
            i += 2
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return "".join(body), i + 1
        body.append(c)
        i += 1
    return None, i


def _split_top_level(body: str) -> list[str]:
    out, cur, depth = [], [], 0
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            cur.append(body[i:i + 2])
            i += 2
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "|" and depth == 0:
            out.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return out


# rule_id -> any-of keyword literals; absent => rule always runs.
_PREFILTER: dict[str, tuple[str, ...]] = {
    rule_id: lits
    for rule_id, _display, pattern in RULES
    if (lits := _prefilter_literals(pattern.pattern))
}

# Manual anchor overrides for rules whose patterns the extractor can't parse.
# Pulled out of _ALWAYS_RUN → ~47% speedup on benign strings.
_PREFILTER.update({
    "stripe-live":         ("sk_live_", "rk_live_"),
    "stripe-test":         ("sk_test_", "rk_test_"),
    "terraform-api-token": ("atlasv1.",),
    "maxmind-license-key": ("_mmk",),
    "freemius-secret-key": ("secret_key",),
})


# Rules with no literal anchor always run; everything else is dispatched by
# which anchors are present in the string.
_ALWAYS_RUN: tuple[int, ...] = tuple(
    i for i, (rid, _d, _p) in enumerate(RULES) if rid not in _PREFILTER)
_LITERAL_RULES: dict[str, list[int]] = {}
for _i, (_rid, _d, _p) in enumerate(RULES):
    for _lit in _PREFILTER.get(_rid, ()):
        _LITERAL_RULES.setdefault(_lit, []).append(_i)

# Single-pass anchor matching. Aho-Corasick (pyahocorasick) finds every
# anchor — including overlapping ones like `git` inside `gitlab` — in one
# O(n) pass, replacing ~189 substring scans per string (~4.7x on real
# histories). If the optional wheel is absent we fall back to the correct
# per-anchor substring check (no behavior change, just the slower path —
# never the lossy single-regex-alternation approach, which would miss a
# literal shadowed by a longer one).
try:
    import ahocorasick as _ahocorasick

    _AC = _ahocorasick.Automaton()
    for _lit, _idxs in _LITERAL_RULES.items():
        _AC.add_word(_lit, tuple(_idxs))
    _AC.make_automaton()

    def _triggered_indices(lowered: str) -> set[int]:
        idx = set(_ALWAYS_RUN)
        for _end, _idxs in _AC.iter(lowered):
            idx.update(_idxs)
        return idx

    PREFILTER_BACKEND = "aho-corasick"
except ImportError:  # pragma: no cover - exercised only without the wheel
    def _triggered_indices(lowered: str) -> set[int]:
        idx = set(_ALWAYS_RUN)
        for lit, idxs in _LITERAL_RULES.items():
            if lit in lowered:
                idx.update(idxs)
        return idx

    PREFILTER_BACKEND = "substring"


# Secrets are short. A single string longer than this is almost always pasted
# data or a serialized cache blob, not a place a secret lives — and scanning a
# multi-MB string against ~190 rules plus the mnemonic detector costs seconds.
# Bound per-string work so one giant value can't stall a scan.
_MAX_SCAN_CHARS = 1_000_000


def scan_text(text: str) -> list[Finding]:
    from .mnemonic import detect_mnemonics  # late import: avoids a cycle

    if len(text) > _MAX_SCAN_CHARS:
        text = text[:_MAX_SCAN_CHARS]
    lowered = text.lower()
    findings: list[Finding] = []
    # sorted() keeps RULES order so overlap dedupe tie-breaks are unchanged.
    for i in sorted(_triggered_indices(lowered)):
        rule_id, display, pattern = RULES[i]
        for m in pattern.finditer(text):
            val = m.group(0)
            findings.append(Finding(
                rule=rule_id,
                display=display,
                value=val,
                masked=mask(val),
                span=(m.start(), m.end()),
            ))
    findings.extend(detect_mnemonics(text))
    findings.sort(key=lambda f: f.span[0])
    return _dedupe_overlapping(findings)


# Function-based detectors (not regex RULES entries). Listed so coverage
# checks — rotation guidance, drift mapping — can account for them.
DETECTOR_IDS: tuple[str, ...] = ("bip39-mnemonic",)


def _dedupe_overlapping(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return findings
    out = [findings[0]]
    for f in findings[1:]:
        last = out[-1]
        if f.span[0] < last.span[1]:
            if (f.span[1] - f.span[0]) > (last.span[1] - last.span[0]):
                out[-1] = f
            continue
        out.append(f)
    return out


ROTATION_GUIDANCE: dict[str, str] = {
    'bip39-mnemonic': 'Move ALL funds to a freshly generated wallet immediately — a leaked seed phrase cannot be rotated, only abandoned. Treat every chain derived from it as compromised.',
    "aws-access-key": "Rotate: aws iam create-access-key, then aws iam delete-access-key --access-key-id <ID>",
    "aws-session-token": "Session tokens are short-lived; rotate the underlying IAM role/user credentials.",
    "github-pat": "Revoke: https://github.com/settings/tokens",
    "github-oauth": "Revoke: https://github.com/settings/applications",
    "github-app": "Rotate via your GitHub App's settings page.",
    "github-fine-grained": "Revoke: https://github.com/settings/tokens?type=beta",
    "stripe-live": "Roll: https://dashboard.stripe.com/apikeys",
    "stripe-test": "Roll: https://dashboard.stripe.com/test/apikeys",
    "openai": "Revoke: https://platform.openai.com/api-keys",
    "anthropic": "Revoke: https://console.anthropic.com/settings/keys",
    "google-api": "Rotate: https://console.cloud.google.com/apis/credentials",
    "google-oauth-client-secret": "Rotate: https://console.cloud.google.com/apis/credentials (OAuth 2.0 Client IDs > reset secret)",
    "google-service-account-key": "Revoke: https://console.cloud.google.com/iam-admin/serviceaccounts (delete the compromised key, generate a new one)",
    "slack-bot": "Rotate: https://api.slack.com/apps (OAuth & Permissions)",
    "slack-user": "Rotate: https://api.slack.com/apps (OAuth & Permissions)",
    "slack-webhook": "Regenerate the webhook in the Slack app that owns it.",
    "huggingface": "Revoke: https://huggingface.co/settings/tokens",
    "jwt": "Invalidate at the issuing service; short-lived tokens may expire naturally.",
    "private-key-pem": "Regenerate the key pair and rotate any authorized_keys / cert stores that reference it.",
    "db-url-with-password": "Change the database user's password and update connection strings.",
    "npm-token": "Revoke: https://www.npmjs.com/settings/~/tokens",
    "pypi-token": "Revoke: https://pypi.org/manage/account/token/",
    "sendgrid": "Rotate: https://app.sendgrid.com/settings/api_keys",
    "twilio": "Rotate: https://console.twilio.com/us1/account/keys-credentials/api-keys",
    "discord-bot-token": "Reset: https://discord.com/developers/applications (your app > Bot > Reset Token)",
    "discord-webhook": "Delete or regenerate the webhook: Server Settings > Integrations > Webhooks (or the channel's Edit Webhook dialog).",
    # --- ported from gitleaks (see scripts/rules_drift.py mapping) ---
    '1password-secret-key': 'Rotate: regenerate the Secret Key in your 1Password account profile (https://support.1password.com/secret-key/)',
    '1password-service-account-token': 'Revoke: https://my.1password.com/developer (Service Accounts > revoke token)',
    'adobe-client-secret': 'Rotate: https://developer.adobe.com/console (Project > Credentials > rotate client secret)',
    'age-secret-key': 'Rotate: generate a new key with `age-keygen` and re-encrypt affected files; age keys cannot be remotely revoked.',
    'airtable-pat': 'Revoke: https://airtable.com/create/tokens',
    'alibaba-access-key-id': 'Rotate: https://ram.console.aliyun.com/manage/ak (disable, then delete the AccessKey pair)',
    'anthropic-admin-key': 'Revoke: https://console.anthropic.com/settings/admin-keys',
    'artifactory-api-key': 'Revoke: your Artifactory instance > Edit Profile > revoke API key (deprecated; or DELETE /api/security/apiKey)',
    'artifactory-reference-token': 'Revoke: JFrog Platform > Administration > User Management > Access Tokens (or DELETE /access/api/v1/tokens/<id>)',
    'atlassian-api-token': 'Revoke: https://id.atlassian.com/manage-profile/security/api-tokens',
    'authress-service-client-key': 'Rotate: https://authress.io/app (Service Clients > rotate access key)',
    'aws-bedrock-api-key-long-lived': 'Revoke: https://console.aws.amazon.com/iam/ (Users > Security credentials > delete the Amazon Bedrock API key)',
    'aws-bedrock-api-key-short-lived': 'Short-lived Bedrock API keys expire automatically (max 12h); revoke the underlying IAM session/credentials if compromised.',
    'azure-ad-client-secret': 'Rotate: https://portal.azure.com (Microsoft Entra ID > App registrations > Certificates & secrets)',
    'clickhouse-cloud-api-secret': 'Rotate: https://console.clickhouse.cloud (organization Settings > API Keys)',
    'clojars-api-token': 'Revoke: https://clojars.org/tokens',
    'cloudflare-origin-ca-key': 'Rotate: https://dash.cloudflare.com/profile/api-tokens (Origin CA Key)',
    'cohere-api-key': 'Revoke: https://dashboard.cohere.com/api-keys',
    'curl-auth-header': 'Rotate the exposed header credential at its issuing service; it was passed on the command line.',
    'curl-auth-user': 'Change the password at the target service; basic-auth credentials were passed on the command line.',
    'databricks-api-token': 'Revoke: Databricks workspace > Settings > Developer > Access tokens (or `databricks tokens delete --token-id <ID>`)',
    'deepseek-api-key': 'Revoke: https://platform.deepseek.com/api_keys',
    'defined-networking-api-token': 'Revoke: https://admin.defined.net (Settings > API keys)',
    'digitalocean-access-token': "Revoke: https://cloud.digitalocean.com/account/api (revoke the OAuth application's authorization)",
    'digitalocean-pat': 'Revoke: https://cloud.digitalocean.com/account/api/tokens',
    'digitalocean-refresh-token': "Revoke: https://cloud.digitalocean.com/account/api (revoke the OAuth application's authorization)",
    'doppler-api-token': 'Revoke: https://dashboard.doppler.com (Settings > Tokens) or `doppler configs tokens revoke`',
    'duffel-api-token': 'Rotate: https://app.duffel.com (Developers > Access tokens)',
    'dynatrace-api-token': 'Revoke: Dynatrace > Access tokens (https://<environment-id>.live.dynatrace.com/ui/access-tokens)',
    'easypost-api-token': 'Rotate: https://www.easypost.com/account/api-keys',
    'easypost-test-api-token': 'Rotate: https://www.easypost.com/account/api-keys',
    'facebook-page-token': 'Revoke: https://developers.facebook.com/tools/debug/accesstoken/ (Invalidate), or reset the app secret in the Meta App Dashboard.',
    'fireworks-api-key': 'Revoke: https://app.fireworks.ai/settings/users/api-keys',
    'flutterwave-encryption-key': 'Rotate: https://app.flutterwave.com/dashboard/settings/apis',
    'flutterwave-public-key': 'Rotate: https://app.flutterwave.com/dashboard/settings/apis',
    'flutterwave-secret-key': 'Rotate: https://app.flutterwave.com/dashboard/settings/apis',
    'flyio-token': 'Revoke: fly tokens revoke <id>, or https://fly.io/user/personal_access_tokens',
    'frameio-token': 'Revoke: https://developer.frame.io/app/tokens',
    'github-refresh-token': "Revoke: https://github.com/settings/applications (minted by a GitHub App's user-to-server flow)",
    'gitlab-cicd-job-token': 'Job tokens expire when the CI job finishes; cancel the running job/pipeline to invalidate early.',
    'gitlab-deploy-token': 'Revoke: GitLab project/group Settings > Repository > Deploy tokens',
    'gitlab-feature-flag-client-token': 'Rotate: GitLab project Deployments > Feature flags > Configure (regenerate the client token)',
    'gitlab-feed-token': 'Reset: https://gitlab.com/-/user_settings/personal_access_tokens (Feed token > reset)',
    'gitlab-incoming-mail-token': 'Reset: https://gitlab.com/-/user_settings/personal_access_tokens (Incoming email token > reset)',
    'gitlab-kubernetes-agent-token': 'Revoke: GitLab project Operate > Kubernetes clusters > select agent > Access tokens',
    'gitlab-oauth-app-secret': 'Rotate: https://gitlab.com/-/user_settings/applications (Renew secret)',
    'gitlab-pat': 'Revoke: https://gitlab.com/-/user_settings/personal_access_tokens',
    'gitlab-pat-routable': 'Revoke: https://gitlab.com/-/user_settings/personal_access_tokens',
    'gitlab-pipeline-trigger': 'Revoke: project Settings > CI/CD > Pipeline trigger tokens (https://gitlab.com/<project>/-/settings/ci_cd)',
    'gitlab-runner-registration': 'Reset: project/group Settings > CI/CD > Runners, or POST /api/v4/runners/reset_registration_token',
    'gitlab-runner-auth': 'Rotate: POST /api/v4/runners/reset_authentication_token, or unregister and re-register the runner',
    'gitlab-runner-auth-routable': 'Rotate: POST /api/v4/runners/reset_authentication_token, or unregister and re-register the runner',
    'gitlab-scim': 'Regenerate: GitLab group Settings > SAML SSO > SCIM token (https://gitlab.com/groups/<group>/-/saml)',
    'gitlab-session-cookie': 'Revoke: sign out the session at https://gitlab.com/-/user_settings/active_sessions',
    'grafana-api-key': 'Revoke: <your-grafana-url>/org/apikeys (Administration > API keys; migrate to service accounts)',
    'grafana-cloud-token': 'Revoke: https://grafana.com/orgs/<org>/access-policies (Cloud Access Policies > delete the token)',
    'grafana-service-account': 'Revoke: <your-grafana-url>/org/serviceaccounts (Administration > Service accounts)',
    'groq-api-key': 'Revoke: https://console.groq.com/keys',
    'harness': 'Rotate: https://app.harness.io (My Profile > My API Keys, or Service Account settings > rotate token)',
    'terraform-api-token': 'Revoke: https://app.terraform.io/app/settings/tokens',
    'heroku-api-key': 'Regenerate: https://dashboard.heroku.com/account (API Key > Regenerate), or heroku authorizations:rotate',
    'huggingface-org': "Revoke: https://huggingface.co/settings/tokens (or the organization's settings > Access Tokens)",
    'infracost': 'Rotate: https://dashboard.infracost.io (Org Settings > API keys)',
    'intra42-client-secret': 'Rotate: https://profile.intra.42.fr/oauth/applications (regenerate the app secret)',
    'jwt-base64': 'Invalidate at the issuing service; short-lived tokens may expire naturally.',
    'linear-api-key': 'Revoke: https://linear.app/settings/api',
    'mailgun-private-token': 'Rotate: https://app.mailgun.com/settings/api_security',
    'mailgun-public-key': 'Rotate: https://app.mailgun.com/settings/api_security',
    'mailgun-signing-key': 'Rotate: https://app.mailgun.com/settings/api_security (HTTP webhook signing key)',
    'mapbox-api-token': 'Rotate: https://console.mapbox.com/account/access-tokens/',
    'maxmind-license-key': 'Rotate: https://www.maxmind.com/en/accounts/current/license-key',
    'microsoft-teams-webhook': 'Remove/recreate the Incoming Webhook in the Teams channel (Manage channel -> Connectors / Workflows).',
    'mistral-api-key': 'Revoke: https://console.mistral.ai/api-keys',
    'new-relic-browser-token': 'Rotate: https://one.newrelic.com/api-keys',
    'new-relic-insert-key': 'Rotate: https://one.newrelic.com/api-keys',
    'new-relic-user-key': 'Rotate: https://one.newrelic.com/api-keys',
    'notion-api-token': "Revoke: https://www.notion.so/my-integrations (refresh the integration's internal secret)",
    'octopus-deploy-api-key': 'Revoke: <your-octopus-server>/app#/users/me/apiKeys (Profile -> My API Keys)',
    'openrouter-api-key': 'Revoke: https://openrouter.ai/settings/keys',
    'openshift-user-token': 'Revoke: oc delete useroauthaccesstoken <token-name> on the cluster',
    'perplexity-api-key': 'Revoke: https://www.perplexity.ai/settings/api',
    'plaid-access-token': 'Rotate: POST /item/access_token/invalidate (Plaid API); manage keys at https://dashboard.plaid.com/developers/keys',
    'planetscale-api-token': 'Revoke: https://app.planetscale.com (Organization settings > Service tokens)',
    'planetscale-oauth-token': 'Revoke: https://app.planetscale.com (Organization settings > OAuth applications)',
    'planetscale-password': 'Rotate: pscale password delete / pscale password create, or https://app.planetscale.com (database > Settings > Passwords)',
    'postman-api-key': 'Revoke: https://go.postman.co/settings/me/api-keys',
    'prefect-api-key': 'Revoke: https://app.prefect.cloud/my/api-keys',
    'pulumi-access-token': 'Revoke: https://app.pulumi.com/account/tokens',
    'readme-api-token': 'Rotate: https://dash.readme.com (project Configuration > API Keys)',
    'rubygems-api-key': 'Revoke: https://rubygems.org/profile/api_keys',
    'scalingo-api-token': 'Revoke: https://dashboard.scalingo.com/account/tokens',
    'sendinblue-api-key': 'Revoke: https://app.brevo.com/settings/keys/api',
    'sentry-org-token': 'Revoke: https://sentry.io/settings/ > (organization) > Auth Tokens',
    'sentry-user-token': 'Revoke: https://sentry.io/settings/account/api/auth-tokens/',
    'settlemint-app-token': 'Revoke: https://console.settlemint.com (application > Access tokens)',
    'settlemint-pat': 'Revoke: https://console.settlemint.com (profile > personal access tokens)',
    'settlemint-sat': 'Revoke: https://console.settlemint.com (application > service access tokens)',
    'shippo': 'Rotate: https://apps.goshippo.com/settings/api',
    'shopify-access-token': 'Rotate: Shopify admin > Settings > Apps and sales channels > Develop apps > (app) > API credentials',
    'shopify-custom-access-token': 'Rotate: uninstall and reinstall the custom app in Shopify admin (Settings > Apps and sales channels) to issue a new token',
    'shopify-private-app-token': 'Rotate: Shopify admin > Settings > Apps and sales channels (private apps are deprecated; regenerate credentials or migrate to a custom app)',
    'shopify-shared-secret': 'Rotate: https://partners.shopify.com (app > API access, rotate client secret)',
    'sidekiq-secret': 'Rotate: email support@contribsys.com to reissue your Sidekiq Enterprise license credentials',
    'sidekiq-sensitive-url': 'Rotate: email support@contribsys.com to reissue your Sidekiq Enterprise license credentials',
    'slack-app-token': 'Revoke: https://api.slack.com/apps (app > Basic Information > App-Level Tokens)',
    'slack-config-access-token': 'Revoke: https://api.slack.com/apps (Your App Configuration Tokens panel)',
    'slack-config-refresh-token': 'Revoke: https://api.slack.com/apps (Your App Configuration Tokens panel)',
    'slack-legacy-token': 'Revoke: https://api.slack.com/methods/auth.revoke (legacy tokens are deprecated)',
    'slack-legacy-workspace-token': 'Revoke: https://api.slack.com/methods/auth.revoke (legacy workspace apps are deprecated)',
    'snyk': 'Revoke: https://app.snyk.io/account (regenerate your API token)',
    'square-access-token': "Rotate: https://developer.squareup.com/apps (open the application's Credentials page and replace the token)",
    'telegram-bot-token': 'Revoke: message @BotFather on Telegram and use /revoke (issues a replacement token)',
    'together-api-key': 'Revoke: https://api.together.ai/settings/api-keys',
    'typeform-token': 'Revoke: https://admin.typeform.com/account#/section/tokens',
    'vault-batch-token': 'Batch tokens cannot be revoked directly; revoke the parent token (vault token revoke <parent>) and let the batch token expire at its TTL.',
    'vault-service-token': 'Revoke: vault token revoke <token> (or vault token revoke -self)',
    'xai-api-key': 'Revoke: https://console.x.ai (API Keys)',
    # --- gitleaks port wave 2 ---
    'adafruit-api-key': 'Revoke: https://io.adafruit.com/user/settings/keys',
    'airtable-api-key': 'Revoke: https://airtable.com/account (API keys section)',
    'algolia-api-key': 'Revoke: https://www.algolia.com/account/api-keys',
    'asana-client-id': 'Revoke: https://app.asana.com/0/my-apps',
    'asana-client-secret': 'Revoke: https://app.asana.com/0/my-apps',
    'beamer-api-token': 'Revoke: https://app.getbeamer.com/settings#api',
    'bitbucket-client-id': 'Revoke: https://bitbucket.org/account/settings/app-passwords/',
    'bitbucket-client-secret': 'Revoke: https://bitbucket.org/account/settings/app-passwords/',
    'bittrex-access-key': 'Revoke: https://bittrex.com/account/settings (API Keys section)',
    'codecov-access-token': 'Revoke: https://app.codecov.io/account/tokens',
    'coinbase-access-token': 'Revoke: https://www.coinbase.com/settings/api',
    'confluent-access-token': 'Revoke: https://confluent.cloud/settings/api-keys',
    'confluent-secret-key': 'Revoke: https://confluent.cloud/settings/api-keys',
    'contentful-delivery-api-token': 'Revoke: https://app.contentful.com/account/profile/cma_tokens',
    'datadog-access-token': 'Revoke: https://app.datadoghq.com/organization-settings/api-keys',
    'discord-api-token': 'Revoke: https://discord.com/developers/applications',
    'dropbox-api-token': 'Revoke: https://www.dropbox.com/developers/apps',
    'dropbox-long-lived-api-token': 'Revoke: https://www.dropbox.com/account/security',
    'dropbox-short-lived-api-token': 'Revoke: https://www.dropbox.com/account/security',
    'droneci-access-token': 'Rotate: https://docs.drone.io/cli/setup/ (drone auth login, generate new token)',
    'fastly-api-token': 'Revoke: https://manage.fastly.com/account/personal/tokens',
    'finicity-client-secret': 'Rotate: https://developer.mastercard.com/open-banking-us/documentation/authenticate/',
    'finnhub-access-token': 'Revoke: https://finnhub.io/dashboard (API Keys section)',
    'flickr-access-token': 'Revoke: https://www.flickr.com/services/apps/ (manage app keys)',
    'freemius-secret-key': 'Revoke: https://freemius.com/help/documentation/developers-api/',
    'freshbooks-access-token': 'Revoke: https://my.freshbooks.com/#/developer (OAuth apps & tokens)',
    'gitter-access-token': 'Revoke: https://developer.gitter.im/apps',
    'gocardless-api-token': 'Revoke: https://manage.gocardless.com/developers/access-tokens',
    'heroku-api-key-legacy': 'Revoke: https://dashboard.heroku.com/account/applications',
    'hubspot-api-key': 'Revoke: https://app.hubspot.com/l/api-key',
    'intercom-api-key': 'Revoke: https://app.intercom.com/a/apps/_/settings/api-keys',
    'jfrog-api-key': 'Revoke: https://jfrog.com/help/r/jfrog-platform-administration-documentation/api-keys',
    'jfrog-identity-token': 'Revoke: https://jfrog.com/help/r/jfrog-platform-administration-documentation/access-tokens',
    'kraken-access-token': 'Revoke: https://www.kraken.com/u/security/api',
    'kucoin-access-token': 'Revoke: https://www.kucoin.com/account/api',
    'kucoin-secret-key': 'Revoke: https://www.kucoin.com/account/api',
    'launchdarkly-access-token': 'Revoke: https://app.launchdarkly.com/settings/authorization',
    'lob-api-key': 'Revoke: https://dashboard.lob.com/settings/api-keys',
    'lob-pub-api-key': 'Revoke: https://dashboard.lob.com/settings/api-keys',
    'mailchimp-api-key': 'Revoke: https://us1.admin.mailchimp.com/account/api/',
    'mattermost-access-token': 'Revoke: <your-mattermost-instance>/user/settings/security (Personal Access Tokens section)',
    'messagebird-api-token': 'Revoke: https://dashboard.messagebird.com/en/developers/access',
    'messagebird-client-id': 'Revoke: https://dashboard.messagebird.com/en/developers/access',
    'netlify-access-token': 'Revoke: https://app.netlify.com/user/applications#personal-access-tokens',
    'sendbird-access-id': 'Revoke: https://dashboard.sendbird.com/settings/general',
    'sonar-api-token': 'Revoke: https://sonarcloud.io/account/security (SonarCloud) or https://<host>/account/security (SonarQube)',
    'sourcegraph-access-token': 'Revoke: https://<your-sourcegraph-instance>/user/settings/tokens',
    'squarespace-access-token': 'Revoke: https://account.squarespace.com/settings/connected-apps',
    'travisci-access-token': 'Revoke: https://app.travis-ci.com/account/preferences (API Authentication -> Revoke Token)',
    'twitch-api-token': 'Revoke: https://dev.twitch.tv/console/apps (Developer Console -> Manage app)',
    'twitter-access-secret': 'Revoke: https://developer.twitter.com/en/portal/projects-and-apps (Keys and tokens)',
    'twitter-access-token': 'Revoke: https://developer.twitter.com/en/portal/projects-and-apps (Keys and tokens)',
    'twitter-api-key': 'Revoke: https://developer.twitter.com/en/portal/projects-and-apps (Keys and tokens)',
    'twitter-api-secret': 'Revoke: https://developer.twitter.com/en/portal/projects-and-apps (Keys and tokens)',
    'twitter-bearer-token': 'Revoke: https://developer.twitter.com/en/portal/projects-and-apps (Bearer Token -> Regenerate)',
    'yandex-api-key': 'Rotate: https://console.cloud.yandex.com/iam (IAM -> Service accounts -> API keys)',
    'yandex-aws-access-token': 'Rotate: https://console.cloud.yandex.com/iam (IAM -> Service accounts -> Static access keys)',
    'yandex-oauth-access-token': 'Revoke: https://oauth.yandex.com/ (Manage tokens -> Revoke)',
}
