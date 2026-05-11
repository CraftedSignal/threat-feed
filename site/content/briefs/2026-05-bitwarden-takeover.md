---
title: Bitwarden Server Missing Authorization Vulnerability Leading to Organization Takeover (CVE-2026-43639)
slug: 2026-05-bitwarden-takeover
description: Bitwarden Server prior to v2026.4.0 contains a missing authorization vulnerability (CVE-2026-43639) that allows a provider service user to add an arbitrary organization to their provider via `POST /providers/{providerId}/clients/existing`, resulting in takeover of the target organization in cloud-hosted deployments.
date: "2026-05-11T18:17:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - bitwarden
  - takeover
  - missing-authorization
  - cloud
vendors:
  - Bitwarden
products:
  - Bitwarden Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-43639
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43639
  - https://github.com/bitwarden/server/commit/0918bfdda6f5eec391c69bd9074f6aef4eac0b1d
  - https://github.com/bitwarden/server/pull/7372
  - https://github.com/bitwarden/server/releases/tag/v2026.4.0
  - https://sanjokkarki.com.np/blog/bitwarden-provider-takeover
  - https://www.vulncheck.com/advisories/bitwarden-server-missing-authorization-via-provider-clients
rules:
  - title: Detect Bitwarden Provider Organization Takeover Attempt
    description: Detects CVE-2026-43639 exploitation — Attempt to add an arbitrary organization to a provider via the /providers/{providerId}/clients/existing endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect High Volume POST Requests to Bitwarden Provider Endpoint
    description: Detects unusual amount of POST request to the Bitwarden provider endpoint which might indicate CVE-2026-43639 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Bitwarden Server before version 2026.4.0 is susceptible to a missing authorization vulnerability identified as CVE-2026-43639. This flaw allows a malicious provider service user in a multi-tenant cloud environment to add an arbitrary organization to their provider account. The vulnerability is located in the `/providers/{providerId}/clients/existing` endpoint. Successful exploitation leads to the takeover of the target organization, granting the attacker unauthorized access and control. Self-hosted Bitwarden installations are not affected as the vulnerable endpoint is exclusively available in the cloud-hosted version due to the `SelfHosted(NotSelfHostedOnly = true)` restriction. This issue was reported by VulnCheck.

## Attack Chain

1. Attacker authenticates as a legitimate provider service user within a Bitwarden Cloud environment.
2. The attacker crafts a malicious `POST` request targeting the `/providers/{providerId}/clients/existing` endpoint.
3. The `providerId` is replaced with the attacker's provider ID.
4. The request body includes data identifying the target organization to be added to the attacker's provider account.
5. Due to the missing authorization check, the server processes the request without validating if the attacker has permission to manage the target organization.
6. The target organization is successfully added to the attacker's provider account.
7. The attacker gains unauthorized access and control over the target organization's Bitwarden data.
8. The attacker can then access sensitive credentials, modify organization settings, and potentially exfiltrate data.

## Impact

Successful exploitation of CVE-2026-43639 allows an attacker to takeover a Bitwarden organization in a cloud-hosted environment. This can lead to significant data breaches, as the attacker gains access to all passwords and secrets stored within the compromised organization's vault. The impact includes potential financial loss, reputational damage, and legal liabilities for the affected organization. The number of potentially affected organizations is limited to Bitwarden's cloud-hosted users.

## Recommendation

*   Upgrade Bitwarden Server to version 2026.4.0 or later to patch CVE-2026-43639.
*   Deploy the Sigma rule "Detect Bitwarden Provider Organization Takeover Attempt" to monitor for suspicious POST requests to the `/providers/{providerId}/clients/existing` endpoint.
*   Monitor web server logs for anomalous POST requests to `/providers/{providerId}/clients/existing` originating from provider service users.
*   Review Bitwarden Cloud provider configurations for any unauthorized organization additions.
