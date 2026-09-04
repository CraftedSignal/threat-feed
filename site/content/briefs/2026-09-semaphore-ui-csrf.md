---
title: Semaphore UI Cross-Site Request Forgery Vulnerability
slug: 2026-09-semaphore-ui-csrf
description: Semaphore UI is vulnerable to a CSRF attack via the password change endpoint, enabling unauthenticated attackers to hijack user accounts, including administrator accounts, by inducing an authenticated user to visit a malicious webpage.
date: "2026-09-04T00:07:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:semaphoreui:semaphore:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - csrf
  - account-takeover
vendors:
  - Semaphore UI
products:
  - Semaphore UI (< 0.0.0-20260707190631-c59c3dc9035b)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An unauthenticated attacker can trick any user, even administrator, to change their password and take control of the semaphore instance.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: 'The password change endpoint of Semaphore UI does not implement any CSRF protection: No CSRF token required, No current password confirmation required.'
    confidence_band: high
cves:
  - id: CVE-2026-73292
    cvss: 8.3
    epss: 0.00237
references:
  - https://github.com/advisories/GHSA-8cj9-r88m-8945
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73292
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Semaphore UI to 0.0.0-20260707190631-c59c3dc9035b or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies this version as the fix for CVE-2026-73292
  mitigation_plan:
    - priority: immediate
      action: Enforce SameSite cookie attributes via reverse proxy or WAF
      owner: Security Engineering
      addresses: CVE-2026-73292
      evidence: Source identifies lack of SameSite enforcement as a primary driver of the CSRF vulnerability
---

Semaphore UI, an open-source automation platform, contains a critical Cross-Site Request Forgery (CSRF) vulnerability (CVE-2026-73292) identified in versions prior to 0.0.0-20260707190631-c59c3dc9035b. The vulnerability stems from the password change endpoint (/api/users/&lt;id>/password) failing to enforce CSRF tokens or require re-authentication via a current password. Additionally, session cookies lack 'SameSite' attribute enforcement, facilitating cross-origin request abuse. By tricking an authenticated user into visiting a crafted malicious page, an attacker can silently execute a password change request. This allows for full account takeover, including the administrative account, depending on the targeted user's privileges. Defenders should prioritize patching, as this vulnerability requires minimal user interaction and leads to complete platform compromise.

## Impact

Successful exploitation results in the takeover of the targeted user's account. Because this vulnerability allows an attacker to change the administrator's password, it can lead to full administrative compromise of the Semaphore UI instance, enabling an attacker to manipulate projects, run arbitrary automation tasks, and potentially escalate access within the organization's infrastructure.

## Recommendation

1. Upgrade Semaphore UI to the latest patched version (>= 0.0.0-20260707190631-c59c3dc9035b) immediately to remediate CVE-2026-73292.
2. Implement global 'SameSite=Strict' or 'SameSite=Lax' cookie policies via load balancers or WAFs if immediate patching is not feasible.
3. Review audit logs for suspicious password change events occurring from unexpected IP addresses or anomalous User-Agent strings.
