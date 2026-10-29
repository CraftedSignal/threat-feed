---
brief_id: brief-2026-10-29-logixfast-auth-bypass
event_id: brief-2026-10-29-logixfast-auth-bypass
revision: 1
activity_at: "2026-10-29T13:19:01Z"
title: 'LogixFast Auth: Password Reset Authentication Bypass (CVE-2026-113616)'
slug: 2026-10-logixfast-auth-bypass
description: An authentication bypass vulnerability in LogixFast Auth before 1.0.4 allows unauthenticated attackers to reset the password of any user by manipulating the destination email address in password reset requests.
date: "2026-10-29T13:19:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Source confirmed; update to version 1.0.4 is the primary remediation
cpes:
  - cpe:2.3:a:logixfast:logixfast_auth:*:*:*:*:*:wordpress:*:*
vendors:
  - LogixFast
products:
  - LogixFast Auth (< 1.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
    subtechnique_id: T1588.006
    subtechnique_name: Vulnerabilities
    evidence: The LogixFast Auth WordPress plugin before 1.0.4 does not deliver its password-reset one-time code to the resolved account's own email address, mailing it to the address supplied in the request instead, allowing unauthenticated attackers to reset any user's password, including an administrator's, and take over the account.
    confidence_band: high
cves:
  - id: CVE-2026-113616
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113616
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade LogixFast Auth to 1.0.4 or later
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable before 1.0.4
  hunt_leads:
    - lead: Search WordPress access logs for multiple password reset requests to the same target username originating from different source IPs or followed by suspicious administrative logins
      technique_id: T1588.006
      data_needed:
        - Web server access logs
        - WordPress authentication/login logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can reset any user's password, including an administrator's
  mitigation_plan:
    - priority: immediate
      action: Upgrade LogixFast Auth to 1.0.4 or later
      owner: IT Operations
      addresses: CVE-2026-113616
      evidence: Version 1.0.4 resolves the password reset routing error
---

The LogixFast Auth WordPress plugin before version 1.0.4 is vulnerable to an authentication bypass flaw. The plugin improperly routes the password reset one-time code to the email address specified in the user-supplied HTTP request rather than the email address linked to the targeted account. This logic error allows unauthenticated attackers to initiate a password reset for any registered user, including administrative accounts, receive the recovery code at an attacker-controlled address, and subsequently perform an account takeover.

## Impact
Successful exploitation allows unauthenticated attackers to achieve full account takeover of any user on the WordPress site. By targeting administrative accounts, attackers can gain complete site control.

## Recommendation
- Upgrade the LogixFast Auth plugin to version 1.0.4 or later immediately.
- Audit WordPress user account logs for suspicious password reset events or unauthorized administrative changes if the plugin was publicly accessible.
