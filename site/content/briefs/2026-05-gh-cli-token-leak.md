---
title: GitHub CLI Incorrectly Includes Authorization Header in API Requests
slug: 2026-05-gh-cli-token-leak
description: GitHub CLI versions 2.92.0 and earlier incorrectly include authorization headers in API requests to TUF repository mirrors and external hosts when using the `gh attestation`, `gh release verify`, and `gh release verify-asset` commands, potentially exposing sensitive tokens.
date: "2026-05-29T15:31:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - github
  - cli
  - token leakage
  - api
vendors:
  - GitHub
  - Microsoft
products:
  - cli/cli/v2
  - Azure Blob Storage
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-8xvp-7hj6-mcj9
  - https://docs.github.com/en/enterprise-cloud@latest/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
  - https://docs.github.com/en/apps/using-github-apps/reviewing-and-revoking-authorization-of-github-apps#reviewing-your-authorized-github-apps
  - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log
  - https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token
iocs:
  - type: domain
    value: tuf-repo.github.com
  - type: domain
    value: tuf-repo-cdn.sigstore.dev
  - type: domain
    value: tmaproduction.blob.core.windows.net
ioc_counts:
  domain: 3
rules:
  - title: Detect GitHub CLI Executing Attestation Commands
    description: Detects the execution of `gh attestation` commands which may be indicative of token leakage vulnerability CVE-2026-48501.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect GitHub CLI Executing Release Verification Commands
    description: Detects the execution of `gh release verify` or `gh release verify-asset` commands which may be indicative of token leakage vulnerability CVE-2026-48501.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

GitHub CLI versions 2.92.0 and earlier contain a vulnerability where authorization headers, including GitHub personal access tokens and enterprise tokens, are incorrectly included in API requests to external hosts. Specifically, the `gh attestation`, `gh release verify`, and `gh release verify-asset` commands fetch data from hosts such as `tuf-repo.github.com`, `tuf-repo-cdn.sigstore.dev`, and `tmaproduction.blob.core.windows.net`. Due to improper host normalization, the CLI's authentication layer attaches tokens intended for `github.com` or GHES instances to these requests. This issue affects authenticated `github.com` users and users with `GH_ENTERPRISE_TOKEN` or `GITHUB_ENTERPRISE_TOKEN` set. Successful exploitation would allow unauthorized access to the token holder's resources.

## Attack Chain

1. A user configures the GitHub CLI with a personal access token or enterprise token.
2. The user executes a `gh attestation`, `gh release verify`, or `gh release verify-asset` command.
3. The GitHub CLI initiates an HTTP request to `tuf-repo.github.com` to retrieve TUF metadata.
4. Due to incorrect host normalization, the CLI attaches the user's `github.com` token to the request header.
5. The GitHub CLI initiates HTTP requests to `tuf-repo-cdn.sigstore.dev` and `tmaproduction.blob.core.windows.net` to retrieve additional TUF metadata and artifact bundles.
6. The CLI erroneously includes the `GH_ENTERPRISE_TOKEN` or `GITHUB_ENTERPRISE_TOKEN` in the headers of these requests.
7. The external hosts receive the unauthorized tokens in the HTTP headers.
8. An attacker who gains access to these hosts could potentially steal the tokens.

## Impact

This vulnerability allows unauthorized access to GitHub tokens, potentially granting an attacker access to private repositories, organization resources, or enterprise administration depending on token type and permissions. Although there is no evidence that tokens were logged, retained, or accessed by unauthorized parties, a captured token would grant the same access as the token holder. This vulnerability is tracked as CVE-2026-48501.

## Recommendation

*   Revoke all authentication tokens used with the GitHub CLI, including personal access tokens and the GitHub CLI OAuth app as described in the [GitHub documentation](https://docs.github.com/en/enterprise-cloud@latest/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).
*   Upgrade the GitHub CLI to version 2.93.0 or later to remediate the vulnerability.
*   Review personal [security logs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log) for any suspicious activity related to your account.
*   Review [audit logs](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token) for any unexpected actions performed by GitHub CLI tokens.
