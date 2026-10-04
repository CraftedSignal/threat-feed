---
title: Authentication Bypass in ZITADEL Identity Provider
slug: 2026-10-zitadel-auth-bypass
description: ZITADEL versions 3.0.0 through 3.4.15 and 4.0.0 through 4.17.2 are vulnerable to an authentication bypass via the AddIDPLink endpoint, allowing unauthenticated attackers to link malicious external IdP identities to victim accounts.
date: "2026-10-04T16:53:24Z"
lastmod: "2026-10-04T16:53:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:zitadel:zitadel:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-105207
  - identity-management
  - web-application
  - vulnerability
vendors:
  - ZITADEL
products:
  - ZITADEL (3.0.0 through 3.4.15)
  - ZITADEL (4.0.0 through 4.17.2)
  - ZITADEL (< 3.4.14, 4.x < 4.16.2)
  - ZITADEL (4.x before 4.17.3, 3.x through 3.4.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An unauthenticated attacker knowing a victim's login name can bind their own external IdP identity to the victim's account and then sign in as the victim.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Unauthenticated attackers can submit forged IDPConfigID and ExternalUserID values to pre-create an account bound to a victim's external IdP identity.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550.001
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who predicts a victim's in-flight intent identifier and wins a timing race can call /v2/idp_intents or /v2/sessions to steal the victim's IdP tokens or hijack their session.
    confidence_band: high
cves:
  - id: CVE-2026-105207
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105207
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105215
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105208
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade ZITADEL to 4.17.3 or 3.4.16
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-105207 remediation
  hunt_leads:
    - lead: Analyze logs for high volume of calls to the AddIDPLink API endpoint
      technique_id: T1133
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source notes vulnerability exists in User Service V2 AddIDPLink endpoint
  mitigation_plan:
    - priority: immediate
      action: Upgrade to fixed versions
      owner: IT Operations
      addresses: CVE-2026-105207
      evidence: Source specifies versions 3.4.16 and 4.17.3 as containing the fix
updates:
  - at: "2026-10-04T16:53:37Z"
    level: L2
    summary: added coverage for ZITADEL (< 3.4.14, 4.x < 4.16.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105215
  - at: "2026-10-04T16:53:50Z"
    level: L2
    summary: added coverage for ZITADEL (4.x before 4.17.3, 3.x through 3.4.15)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-105208
---

ZITADEL identity management software contains a critical authentication bypass vulnerability (CVE-2026-105207) affecting versions 3.0.0 through 3.4.15 and 4.0.0 through 4.17.2. The vulnerability exists within the User Service V2 AddIDPLink endpoint and certain Login V2 session flows. The software fails to verify primary authentication factors or caller permissions when establishing links between local user accounts and external identity providers (IdPs). An unauthenticated attacker who knows a target user's login name can exploit this by binding their own controlled external IdP identity to the victim's account. Once the link is established, the attacker can leverage the external IdP to authenticate as the victim, effectively bypassing standard password or MFA requirements. This issue is particularly severe as it allows for full account takeover without user interaction or prior knowledge of the victim's password.

## Impact

Successful exploitation allows unauthenticated attackers to gain unauthorized access to any user account within the affected ZITADEL instance. This may lead to total account compromise, exfiltration of sensitive user data, unauthorized access to downstream applications integrated with the identity provider, and potential escalation of privileges depending on the target user's roles within the ZITADEL platform.

## Recommendation

- Upgrade ZITADEL installations immediately to version 3.4.16 or 4.17.3 to address CVE-2026-105207.
- Audit existing external IdP links within the ZITADEL administrative console to identify any unauthorized or suspicious bindings created during the window of vulnerability.
- Review web server access logs for repeated requests to the User Service V2 AddIDPLink endpoint from unrecognized or anomalous source IP addresses.
