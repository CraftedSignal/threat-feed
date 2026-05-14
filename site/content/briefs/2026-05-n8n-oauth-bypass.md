---
title: n8n Cross-User Authorization Bypass in Dynamic Credential OAuth Endpoints (CVE-2026-45732)
slug: 2026-05-n8n-oauth-bypass
description: CVE-2026-45732 describes a high-severity authorization bypass vulnerability in n8n's OAuth1 and OAuth2 credential reconnect endpoints, where insufficient permission checks allow a user with read-only access to overwrite OAuth tokens, potentially leading to data exfiltration and persistent takeover of shared integrations.
date: "2026-05-14T16:25:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - oauth
  - credential-theft
vendors:
  - n8n GmbH
products:
  - n8n (< 1.123.43)
  - n8n (>= 2.21.0, < 2.21.1)
  - n8n (>= 2.0.0-rc.0, < 2.20.7)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://github.com/advisories/GHSA-6h4j-wcr9-2vg7
  - CVE-2026-45732
rules:
  - title: Detect CVE-2026-45732 Exploitation Attempt - Suspicious Credential Reconnect
    description: Detects potential exploitation attempts of CVE-2026-45732 by monitoring for suspicious credential reconnect activities initiated by users with only read permissions, based on unusual API calls or user agent patterns.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-45732
      - initial_access
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect n8n Credential Reconnect Tampering via API Endpoint
    description: Detects potential tampering with n8n credentials by monitoring for POST requests to the /api/v1/credentials/{credentialId}/reconnect endpoint, which could indicate an attempt to exploit CVE-2026-45732.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-45732
      - persistence
      - privilege_escalation
    data_sources:
      - webserver
rules_count: 2
---

A cross-user authorization bypass vulnerability exists in n8n's Dynamic Credential OAuth endpoints. Specifically, the OAuth1 and OAuth2 credential reconnect endpoints incorrectly authorized access using `credential:read` instead of the necessary `credential:update` permission. This flaw allows an authenticated user with only read-only access to a shared credential to initiate an OAuth reconnect flow. By doing so, the attacker can overwrite the stored token material for the credential with tokens bound to an external account under their control. This can lead to workflows relying on the compromised credential executing under the attacker's OAuth identity. The issue affects n8n versions before 1.123.43, versions between 2.0.0-rc.0 and 2.20.7, and versions between 2.21.0 and 2.21.1.

## Attack Chain

1. An attacker gains access to an n8n instance with shared credentials.
2. The attacker identifies a shared credential to which they have read-only access.
3. The attacker navigates to the OAuth1 or OAuth2 credential reconnect endpoint for the target credential.
4. Due to the authorization bypass (CVE-2026-45732), the attacker is able to initiate an OAuth reconnect flow despite lacking update permissions.
5. The attacker authenticates with their own external OAuth provider account.
6. The attacker's OAuth tokens are used to overwrite the existing tokens for the shared credential.
7. Workflows using the shared credential now execute under the attacker's OAuth identity.
8. The attacker can exfiltrate data to attacker-controlled external services or maintain persistent access to shared integrations.

## Impact

Successful exploitation of this vulnerability (CVE-2026-45732) allows an attacker to overwrite OAuth tokens in shared credentials, leading to data exfiltration to attacker-controlled external services. This can result in persistent takeover of shared integrations, potentially impacting multiple users or projects that rely on the compromised credential. The affected instances are those where credentials are shared with other users or across projects, creating a significant risk of unauthorized access and data breaches.

## Recommendation

- Upgrade n8n to version 1.123.43, 2.20.7, 2.21.1, or later to remediate CVE-2026-45732 as advised in the advisory.
- If immediate upgrade is not possible, restrict credential sharing to fully trusted users as a temporary mitigation.
- Audit shared credentials for unexpected OAuth token changes and revoke any tokens that may have been replaced as an additional short-term measure.
