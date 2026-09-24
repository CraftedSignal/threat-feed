---
title: ZITADEL Login V2 MFA Bypass via Session Reuse
slug: 2026-09-zitadel-mfa-bypass
description: A session-reuse vulnerability in ZITADEL Login V2 (CVE-2026-85056) allows attackers with valid credentials to bypass MFA by abandoning and restarting the login flow in organizations where MFA is not strictly enforced.
date: "2026-09-24T20:07:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zitadel:login_v2:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - mfa-bypass
  - cve-2026-85056
vendors:
  - ZITADEL
products:
  - ZITADEL Login V2 (4.0.0-4.16.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: A vulnerability in ZITADEL Login V2 UI allowed a password-verified browser session to be reused for a new authentication request without re-checking a user enrolled second factor.
    confidence_band: high
cves:
  - id: CVE-2026-85056
    cvss: 8.2
references:
  - https://github.com/advisories/GHSA-9993-rfwp-rhwf
  - https://github.com/zitadel/zitadel/releases/tag/v4.16.1
action_plan:
  priority: immediate_escalation
  owners:
    - IAM Administration
    - SOC
  immediate_actions:
    - action: Upgrade ZITADEL to 4.16.1 or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to >= 4.16.1 for CVE-2026-85056.
  mitigation_plan:
    - priority: immediate
      action: Enable 'Force MFA' in login policy for affected instances.
      owner: IAM Administration
      addresses: CVE-2026-85056
      evidence: Source identifies 'Force MFA' as the primary workaround to close the session reuse bypass.
---

ZITADEL's Login V2 UI contains a vulnerability, tracked as CVE-2026-85056, that permits an authentication bypass for users who have enrolled in multi-factor authentication (MFA) but are not subject to mandatory 'Force MFA' policies. The issue arises from the way the Login V2 UI handles browser sessions: it issues a session token immediately upon successful password verification, before the secondary authentication factor is satisfied. If a user or an attacker triggers the login process, completes password authentication, and then abandons the MFA prompt, the resulting session remains partially authenticated. By restarting the login flow, the system incorrectly reuses the existing password-verified session to finalize the authentication to OIDC or SAML-integrated applications, bypassing the requirement for the second factor.

The vulnerability is limited to the hosted Login V2 interface and does not impact internal ZITADEL console access or administration APIs. It specifically affects ZITADEL versions 4.0.0 through 4.16.0.

## Impact

Successful exploitation allows an attacker possessing valid user credentials (such as via phishing or credential stuffing) to gain unauthorized access to target applications protected by ZITADEL. Because this bypass effectively negates the security provided by TOTP, OTP, or U2F, it significantly increases the risk of account takeover. Organizations that do not have 'Force MFA' policies enabled for all users are at risk, as the system fails to treat voluntarily enrolled MFA as a mandatory barrier during the session reuse event.

## Recommendation

Prioritized actions for security and identity teams:

- Upgrade ZITADEL installations to version 4.16.1 or later immediately to address the underlying session logic vulnerability.
- If immediate patching is not possible, modify the organization's login policy to enable 'Force MFA' or 'Force MFA for local users only'. This mitigates the risk by making second-factor verification mandatory for all relevant authentication requests, effectively closing the bypass vector.
- Audit logs for unexpected OIDC/SAML callback completions where MFA verification events are absent despite MFA enrollment for the user account.
