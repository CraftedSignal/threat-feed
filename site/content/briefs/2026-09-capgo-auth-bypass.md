---
title: Authentication Bypass in Capgo via MFA Assurance Level Validation Failure
slug: 2026-09-capgo-auth-bypass
description: Capgo contains an authentication bypass vulnerability allowing attackers with a user password to ignore MFA requirements and mint persistent administrative API keys by exploiting improper session assurance level validation.
date: "2026-09-10T15:10:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:capgo:capgo:*:*:*:*:*:*:*:*
vendors:
  - Capgo
products:
  - Capgo (all versions)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: An attacker who knows only the victim's password can therefore authenticate, mint a persistent app-scoped app_admin API key that remains valid after the aal1 session is logged out.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: mint a persistent app-scoped app_admin API key that remains valid after the aal1 session is logged out
    confidence_band: high
cves:
  - id: CVE-2026-88861
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88861
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Monitor administrative audit logs for API key generation events
      owner: SOC
      due: 24h
      evidence: Exploitation allows minting persistent app-scoped API keys
  hunt_leads:
    - lead: Identification of API keys with administrative scopes generated during aal1 sessions
      technique_id: T1550
      data_needed:
        - Capgo administrative audit logs
        - Session assurance level metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: RBAC functions authorize by user ID without checking the session aal
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access to authorized IP ranges
      owner: IT Operations
      addresses: CVE-2026-88861
      evidence: No patch currently available for this vulnerability
---

Capgo (capgo.app) contains an authentication bypass vulnerability (CVE-2026-88861) that affects all versions, as no patch is currently available. The vulnerability exists within the Edge authorization path, where the middleware fails to validate the session authentication assurance level (aal). Specifically, the `foundJWT()` function in the Edge JWT middleware accepts JSON Web Tokens without confirming if the session met MFA requirements. Furthermore, the internal RBAC functions (`checkPermission()` and `checkPermissionPg()`) authorize administrative actions based solely on the user ID rather than the session aal. Consequently, an attacker who acquires a victim's password can initiate an aal1 session, effectively bypassing configured MFA to perform unauthorized operations, including the creation of persistent app-scoped API keys that remain active after the initial session is terminated. This impact is significant as it allows attackers to modify production Over-The-Air (OTA) channel configurations, potentially leading to unauthorized code distribution.

## Impact

Successful exploitation allows an unauthenticated or partially authenticated attacker to bypass multi-factor authentication, gain persistent administrative access, and manipulate sensitive production OTA channel configurations. This vulnerability impacts all users of the Capgo platform, as no mitigation is currently available, creating a risk of unauthorized supply chain modification if production bundles are altered by unauthorized parties.

## Recommendation

Prioritized actions for security operations and IT teams:
- Implement strict IP-based access controls for the Capgo administrative dashboard to mitigate potential password-guessing or credential-stuffing attempts against the aal1-enabled endpoints.
- Audit existing API keys for unexpected creation dates or unauthorized administrative scopes.
- Monitor logs for unusual modifications to production OTA channel configurations, specifically looking for changes in bundle versions originating from unknown or unauthorized administrative sessions.
- Enforce hardware-backed security keys or restrict administrative access to specific managed devices if the platform allows integration with external SSO/IAM providers.
