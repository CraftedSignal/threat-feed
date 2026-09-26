---
title: Authentication Bypass in stoatchat via MFA Ticket Manipulation
slug: 2026-09-stoatchat-mfa-bypass
description: stoatchat versions prior to 0.15.5 are vulnerable to an authentication bypass where attackers can use their own MFA ticket to authenticate against a victim's session.
date: "2026-09-26T17:00:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:stoatchat:stoatchat:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - mfa-bypass
  - cve-2026-100679
vendors:
  - stoatchat
products:
  - stoatchat (< 0.15.5)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can obtain a ticket from their own account and use it with a victim's session token to disable TOTP, view recovery codes, or perform other sensitive operations without providing the victim's credentials.
    confidence_band: high
cves:
  - id: CVE-2026-100679
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100679
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade stoatchat to version 0.15.5 or later
      owner: IT Operations
      due: 24h
      evidence: stoatchat before 0.15.5 fails to validate that MFA tickets belong to the authenticated user
  mitigation_plan:
    - priority: immediate
      action: Upgrade stoatchat to version 0.15.5 or later
      owner: IT Operations
      addresses: CVE-2026-100679
      evidence: Source documentation for CVE-2026-100679
---

CVE-2026-100679 identifies a critical authentication vulnerability in the stoatchat application (versions prior to 0.15.5). The vulnerability stems from an improper validation of Multi-Factor Authentication (MFA) tickets during the session authentication process. Specifically, the application fails to verify that a provided MFA ticket is cryptographically or logically bound to the session token of the user currently attempting to authenticate.

An unauthenticated or authenticated attacker can exploit this flaw by obtaining a valid MFA ticket from their own legitimate account and subsequently injecting it into an HTTP request alongside a compromised or targeted user's session token. If successful, the server accepts the attacker-provided ticket as valid for the victim's session, effectively bypassing the TOTP or MFA challenge. This allows the attacker to gain unauthorized access to sensitive account settings, view recovery codes, or disable MFA entirely without knowledge of the victim's second-factor device. Defenders should prioritize upgrading to version 0.15.5 or later to enforce proper MFA session binding.

## Impact

The vulnerability allows for the complete bypass of MFA protections within the stoatchat platform. If exploited, attackers can gain unauthorized access to victim accounts, leading to sensitive data exposure, potential account takeover, and the permanent removal of secondary security controls. This presents a high risk to all users and organizations relying on stoatchat for secure communication or data management.

## Recommendation

1. Upgrade all stoatchat instances to version 0.15.5 or later immediately to patch CVE-2026-100679.
2. Audit application logs for abnormal MFA authentication patterns, specifically multiple successful MFA validations originating from different session identifiers within short timeframes.
3. Force session invalidation for all active users following the deployment of the security patch.
