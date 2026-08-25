---
title: Authorization Bypass in Grav Login Plugin
slug: 2026-08-grav-plugin-auth-bypass
description: An authorization flaw in the Grav Login plugin (pre-1.0.16) allows users with restricted permissions to reset lockout counters for administrative accounts, facilitating brute-force attacks.
date: "2026-08-25T04:05:15Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - getgrav
products:
  - Login plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker with api.users.write permission can clear login lockout counters on admin.super accounts, removing brute-force protection from the highest-privilege accounts without requiring equivalent permissions.
    confidence_band: high
cves:
  - id: CVE-2026-56710
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56710
  - https://github.com/getgrav/grav/security/advisories/GHSA-985r-mpj8-5rqw
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Grav Login plugin to version 1.0.16
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-56710
  hunt_leads:
    - lead: API calls to the unlock handler in conjunction with administrative account login failures
      technique_id: T1068
      data_needed:
        - Web server logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: Vulnerability allows clearing of lockout counters via the onApiUserListRowAction handler.
---

Grav Login plugin versions before 1.0.16 are vulnerable to an improper authorization flaw (CWE-863) within the onApiUserListRowAction unlock handler. This vulnerability enables an attacker who already possesses api.users.write permissions to clear login lockout counters for accounts with admin.super privileges. By successfully resetting these counters, an attacker can effectively neutralize brute-force protection mechanisms for the highest-privilege accounts in the system. This significantly increases the risk of successful account takeover via automated credential-guessing attacks. Defenders should prioritize updating the Grav Login plugin to version 1.0.16 or later to enforce proper privilege validation during the unlock process.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass existing security controls intended to prevent brute-force attacks against administrative accounts. By resetting lockout counters, attackers can maintain persistent attempts to compromise administrative credentials without the risk of the account being locked, potentially leading to full administrative compromise of the Grav instance.

## Recommendation

- Upgrade the Grav Login plugin to version 1.0.16 or later immediately.
- Audit accounts with the api.users.write permission to ensure that only authorized users or services maintain this capability.
- Review web server logs for suspicious API requests directed at the onApiUserListRowAction handler that correlate with repeated failed login attempts against administrative users.
