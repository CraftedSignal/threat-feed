---
title: Authentication Bypass in Better Auth @better-auth/sso
slug: 2026-10-better-auth-sso-bypass
description: Better Auth @better-auth/sso versions 1.7.0-rc.2 through 1.7.2 contain an authentication bypass vulnerability allowing attackers to impersonate other users via malicious SSO provider registration.
date: "2026-10-15T02:34:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:better-auth:better-auth:*:*:*:*:*:node.js:*:*
tags:
  - authentication-bypass
  - identity-management
  - cve-2026-110863
vendors:
  - Better Auth
products:
  - '@better-auth/sso (1.7.0-rc.2 to 1.7.2)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: An authenticated attacker can impersonate other users by configuring a malicious SSO provider using a legitimate OIDC issuer or SAML entity ID, enabling them to assert arbitrary user identifiers and create unauthorized sessions.
    confidence_band: high
cves:
  - id: CVE-2026-110863
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110863
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade @better-auth/sso to version 1.7.3 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110863 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade @better-auth/sso to 1.7.3
      owner: IT Operations
      addresses: CVE-2026-110863
      evidence: NVD vulnerability resolution
---

The Better Auth library, specifically the @better-auth/sso package, is affected by an authentication bypass vulnerability identified as CVE-2026-110863. The vulnerability exists in versions 1.7.0-rc.2 through 1.7.2. It stems from a flaw in the account lookup logic during the registration of personal SSO providers. Specifically, the system fails to validate the 'providerId' field when processing OIDC or SAML assertions. An authenticated user can configure a malicious SSO provider using the issuer URL or entity ID of a legitimate provider already associated with the target application. By asserting the 'subject' or 'NameID' of a victim user, the attacker can force the application to associate the incoming authentication event with the victim's account, effectively bypassing standard authentication controls and gaining unauthorized access to the victim's session.

## Impact

Successful exploitation allows an authenticated attacker to impersonate any user within the application, leading to complete account takeover and unauthorized access to sensitive user data and administrative functions. The severity is rated at 8.1 (CVSS v3.1), reflecting the potential for significant impact on confidentiality and integrity for applications relying on the @better-auth/sso component for identity management.

## Recommendation

* Upgrade the @better-auth/sso package to version 1.7.3 or later immediately.
* Audit logs for suspicious SSO provider registration events or unexpected authentication assertions involving the 'providerId' field.
* Review current SSO provider configurations for any anomalies where multiple providers share identical OIDC issuer strings or SAML entity IDs.
