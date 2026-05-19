---
title: GitHub Actions GITHUB_TOKEN Disclosure via Composer Validation Failure
slug: 2026-05-github-token-disclosure
description: Composer leaks GitHub OAuth tokens in GitHub Actions logs if they do not match the expected format due to a validation regex, leading to potential unauthorized access.
date: "2026-05-19T16:18:49Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - github
  - actions
  - composer
  - token-leak
  - cve-2026-45793
vendors:
  - GitHub
products:
  - github.com
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-f9f8-rm49-7jv2
  - CVE-2026-45793
rules:
  - title: Detect GITHUB_TOKEN Leak in Composer Logs
    description: Detects potential GITHUB_TOKEN leaks in GitHub Actions logs due to Composer validation failures.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - webserver
  - title: Detect Composer Validation Errors with Hyphens in Tokens
    description: Detects Composer throwing validation errors due to hyphens in GitHub tokens.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in Composer that leads to the disclosure of GitHub OAuth tokens, including the `GITHUB_TOKEN` in GitHub Actions logs. This occurs when tokens do not match Composer's expected format, specifically those containing hyphens introduced in GitHub's new token format (`ghs_<id>_<base64url-JWT>`). Widely-used actions often auto-register the `GITHUB_TOKEN` into Composer's global `auth.json`, triggering the leak without specific user configuration. While GitHub Actions tokens expire rapidly (within 6 hours on GitHub-hosted runners and 24 hours on self-hosted runners) and are scoped to the repository, the exposure poses a risk if the token is captured before expiration. This issue is tracked as CVE-2026-45793 and affects Composer versions 2.3.0-2.9.7, 2.0.0-2.2.27 and 1.0-1.10.27.

## Attack Chain

1. A GitHub Actions workflow is triggered.
2. The workflow utilizes an Action (e.g., `shivammathur/setup-php`) that automatically registers the `GITHUB_TOKEN` into Composer's global `auth.json`.
3. Composer attempts to validate the `GITHUB_TOKEN` using a regular expression (`^[.A-Za-z0-9_]+$`) in `Composer\IO\BaseIO::loadConfiguration()`.
4. The validation fails because the `GITHUB_TOKEN` now contains a hyphen (`-`) due to the new GitHub token format.
5. Composer throws an `UnexpectedValueException` containing the full, unmasked `GITHUB_TOKEN` in the exception message.
6. Symfony Console, used by Composer, renders the exception message to stderr.
7. The stderr output, including the plaintext `GITHUB_TOKEN`, is captured in GitHub Actions logs.
8. An attacker with access to the logs can then steal the leaked token. The attacker could use the leaked credentials to make unauthorized API calls to Github on behalf of the workflow, with scopes limited to the respective repository.

## Impact

The vulnerability results in the exposure of sensitive `GITHUB_TOKEN` values in GitHub Actions logs, which could allow unauthorized access to repository resources. Though tokens expire quickly and are repository-scoped, successful exploitation could lead to code modification, data exfiltration, or other malicious activities within the compromised repository before the token expires.

## Recommendation

*   Deploy the Sigma rule "Detect GITHUB_TOKEN Leak in Composer Logs" to your SIEM to identify potential token leaks within GitHub Actions logs.
*   Upgrade to Composer version 2.9.8, 2.2.28 or 1.10.28 or later to address the vulnerability (CVE-2026-45793).
*   Monitor GitHub Actions logs for unexpected error messages related to Composer token validation failures.
*   Rotate `GITHUB_TOKEN` secrets if a leak is suspected to invalidate potentially compromised credentials.
