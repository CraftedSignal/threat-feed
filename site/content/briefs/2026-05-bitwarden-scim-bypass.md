---
title: Bitwarden Server SCIM API Key Authentication Bypass (CVE-2026-43640)
slug: 2026-05-bitwarden-scim-bypass
description: Bitwarden Server before v2026.4.1 allows an authenticated user with SCIM management privileges to bypass master-password re-authentication when retrieving or rotating an organization's SCIM API key, potentially leading to unauthorized access.
date: "2026-05-11T18:18:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - privilege-escalation
  - cve
vendors:
  - Bitwarden
products:
  - Bitwarden Server
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-43640
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43640
  - https://github.com/bitwarden/server/commit/eb251d9bf80724c87b187661783b9354d1784083
  - https://github.com/bitwarden/server/pull/7403
  - https://github.com/bitwarden/server/releases/tag/v2026.4.1
  - https://sanjokkarki.com.np/blog/bitwarden-scim-key-bypass
  - https://www.vulncheck.com/advisories/bitwarden-server-authentication-bypass-via-scim-api-key
rules:
  - title: Detects CVE-2026-43640 Exploitation Attempt — SCIM API Key Retrieval without MFA
    description: Detects CVE-2026-43640 exploitation attempt — Monitors for requests to the SCIM API key retrieval endpoint without a corresponding MFA challenge in Bitwarden Server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1555.005
    data_sources:
      - webserver
  - title: Detects CVE-2026-43640 Exploitation Attempt — SCIM API Key Rotation without MFA
    description: Detects CVE-2026-43640 exploitation attempt — Monitors for requests to rotate the SCIM API key without a corresponding MFA challenge in Bitwarden Server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1555.005
    data_sources:
      - webserver
rules_count: 2
---

Bitwarden Server prior to version v2026.4.1 is vulnerable to an authentication bypass. The vulnerability, identified as CVE-2026-43640, allows an authenticated user with SCIM (System for Cross-domain Identity Management) management privileges to retrieve or rotate an organization's SCIM API key without requiring master-password re-authentication. This means that if an attacker gains access to a valid user session with SCIM management privileges, they can obtain the SCIM API key without needing to know the user's master password. The issue stems from an incorrect implementation of the authentication algorithm (CWE-303). This can lead to unauthorized access to sensitive resources managed through the SCIM API.

## Attack Chain

1. An attacker gains initial access to a Bitwarden Server account with SCIM management privileges, potentially through credential stuffing or phishing.
2. The attacker authenticates to the Bitwarden Server web interface using the compromised credentials.
3. The attacker navigates to the organization settings related to SCIM configuration.
4. Instead of being prompted for master password re-authentication, the attacker is granted access to retrieve the SCIM API Key.
5. The attacker retrieves the existing SCIM API key.
6. Alternatively, the attacker can initiate a SCIM API key rotation, generating a new key without master password verification.
7. The attacker uses the obtained SCIM API key to access and manage user accounts and groups within the organization's identity provider.
8. The attacker could create new admin accounts, modify existing ones, or exfiltrate sensitive user data.

## Impact

Successful exploitation of CVE-2026-43640 can lead to a complete compromise of the affected organization's identity management. An attacker with a valid user session with SCIM management privileges can obtain the SCIM API key and use it to perform unauthorized actions, such as creating new administrative accounts, modifying existing user accounts, or exfiltrating sensitive user data. This vulnerability affects all Bitwarden Server instances prior to version v2026.4.1.

## Recommendation

*   Upgrade Bitwarden Server to version v2026.4.1 or later to patch CVE-2026-43640.
*   Monitor Bitwarden Server logs for unusual activity related to SCIM API key retrieval or rotation, using the log source `webserver`.
*   Implement multi-factor authentication (MFA) on all Bitwarden accounts, especially those with administrative privileges.
*   Deploy the Sigma rule provided below to detect potential exploitation attempts.
