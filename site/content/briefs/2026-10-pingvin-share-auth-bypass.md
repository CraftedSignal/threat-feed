---
title: Improper Authentication Vulnerability in Pingvin Share
slug: 2026-10-pingvin-share-auth-bypass
description: Pingvin Share versions 0.19.0 through 1.21.x contain an authentication bypass vulnerability (CVE-2026-108157) allowing attackers to perform account takeover by exploiting improper email verification during OAuth registration.
date: "2026-10-09T17:27:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pingvinshare:pingvin_share:*:*:*:*:*:*:*:*
vendors:
  - Pingvin Share
products:
  - Pingvin Share (0.19.0 <= version < 1.22.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556.002
    technique_name: 'Modify Authentication Process: Multi-Factor Authentication'
    evidence: The vulnerability allows attackers to register a victim's unverified email on an enabled OAuth/OIDC provider to sign in as the victim while bypassing TOTP.
    confidence_band: high
cves:
  - id: CVE-2026-108157
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108157
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Pingvin Share to 1.22.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108157 remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Pingvin Share 1.22.0
      owner: IT Operations
      addresses: CVE-2026-108157
      evidence: Vendor patch information
---

Pingvin Share versions 0.19.0 through 1.21.x are affected by an improper authentication vulnerability, tracked as CVE-2026-108157. The vulnerability exists within the OAuthService.signUp() function and the GenericOidcProvider, where the application fails to validate the email_verified claim when performing OAuth or OpenID Connect (OIDC) registrations. A remote, unauthenticated attacker can exploit this flaw by registering an arbitrary email address associated with an enabled OAuth/OIDC provider. By doing so, the attacker can associate their own OIDC registration with a victim's email address, effectively taking over the victim's account. This method bypasses existing password protections and Multi-Factor Authentication (MFA) requirements, including TOTP. Because administrative accounts can be targeted, this vulnerability presents a critical risk for unauthorized access and administrative control over the Pingvin Share instance.

## Impact

Successful exploitation allows for full account takeover of any user within the target Pingvin Share instance, including administrative accounts. Attackers can bypass all secondary authentication mechanisms, including TOTP, leading to potential data exfiltration, unauthorized file sharing, and full administrative configuration control of the application.

## Recommendation

1. Upgrade Pingvin Share to version 1.22.0 or later immediately to address CVE-2026-108157.
2. Audit user account modifications and unexpected OAuth provider associations within the application logs for activity matching account registration timeframes.
3. Temporarily disable OIDC/OAuth registration if immediate patching is not possible and monitor application access logs for unusual registration patterns.
