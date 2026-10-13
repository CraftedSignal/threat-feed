---
title: Authentication Bypass Vulnerability in Ikaros
slug: 2026-10-ikaros-auth-bypass
description: Ikaros versions 1.2.0 through 1.2.5 are vulnerable to an authentication bypass where attackers with valid passwords can circumvent TOTP requirements by manipulating temporary login tokens.
date: "2026-10-13T18:37:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ikaros:ikaros:1.2.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ikaros:ikaros:1.2.5:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - ikaros
  - vulnerability
vendors:
  - Ikaros
products:
  - Ikaros (1.2.0 - 1.2.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The vulnerability allows attackers to reuse login temp tokens or present them as bearer JWTs to bypass TOTP.
    confidence_band: high
cves:
  - id: CVE-2026-110097
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110097
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Ikaros to a patched version post-1.2.5
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-110097
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the Ikaros authentication endpoints
      owner: IT Operations
      addresses: CVE-2026-110097
      evidence: Authentication bypass vulnerability
---

Ikaros versions 1.2.0 through 1.2.5 contain a critical authentication bypass vulnerability (CVE-2026-110097) that enables attackers who possess a legitimate user password to circumvent Multi-Factor Authentication (TOTP). The vulnerability stems from improper handling of temporary tokens issued during the initial login phase. An attacker can intercept or reuse a temp token obtained from the '/jwt/apply' endpoint. By presenting this token as a valid bearer JWT or refreshing it, the attacker can successfully bypass the second factor of authentication. This flaw allows for full account takeover, including the acquisition of master administrator privileges, significantly increasing the risk of lateral movement and data exfiltration within the affected environment. Organizations utilizing Ikaros should immediately restrict access to the application interface and prioritize the application of vendor-supplied patches to remediate this authentication logic flaw.

## Impact

Successful exploitation of this vulnerability allows unauthorized actors to bypass security controls, leading to total account compromise. In environments where master administrator accounts are targeted, attackers can gain full control over the application, modify configurations, and access sensitive data. Given the severity of the authentication bypass, the potential for unauthorized access is high for all exposed instances of Ikaros within the 1.2.0 to 1.2.5 version range.

## Recommendation

* Prioritize the immediate upgrade of all Ikaros instances to a patched version that resolves CVE-2026-110097.
* Monitor web server logs for suspicious activity targeting the '/jwt/apply' endpoint, specifically looking for anomalous sequences of HTTP Basic login followed by token reuse as a bearer token.
* Restrict external access to the Ikaros login portal via network-level controls until patches are verified and applied.
