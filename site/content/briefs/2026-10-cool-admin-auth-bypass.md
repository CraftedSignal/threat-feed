---
title: Authorization Bypass in cool-admin-midway
slug: 2026-10-cool-admin-auth-bypass
description: An authorization bypass vulnerability in cool-admin-midway through version 8.0.0 allows department-restricted administrators to perform unauthorized administrative actions on users outside their assigned scope.
date: "2026-10-15T22:50:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cool_admin:cool_admin_midway:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authorization-bypass
  - api-security
vendors:
  - cool-admin
products:
  - cool-admin-midway (<= 8.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers holding sys:user:* permissions can call /admin/sys/user/info, update, or delete to read records, reset passwords and roles, or delete accounts.
    confidence_band: high
cves:
  - id: CVE-2026-111366
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111366
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit logs for anomalous administrative actions on /admin/sys/user/ endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-111366 disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade cool-admin-midway beyond 8.0.0
      owner: IT Operations
      addresses: CVE-2026-111366
      evidence: NVD vulnerability disclosure
---

CVE-2026-111366 is an authorization bypass vulnerability affecting the cool-admin-midway framework up to version 8.0.0. The vulnerability resides in the administrative API handling, where validation logic fails to enforce department-level scoping for users possessing 'sys:user:*' permissions. This flaw allows an authenticated administrator, limited to specific departments, to manipulate user data belonging to other departments by submitting arbitrary user IDs in API requests. Successful exploitation enables unauthorized record retrieval, password resets, role modification, and account deletion. Given that this vulnerability permits privilege escalation by manipulating administrative access controls, it poses a significant risk to organizations using the affected framework for user management.

## Impact

Successful exploitation allows an attacker to compromise the integrity and confidentiality of user accounts system-wide. Unauthorized actors can perform administrative functions across the entire user base, bypassing organizational department boundaries. This can lead to mass account compromise, privilege escalation, and data exfiltration.

## Recommendation

- Upgrade cool-admin-midway to a patched version beyond 8.0.0 as soon as it becomes available.
- Audit logs for administrative actions (e.g., password resets, role updates, account deletions) initiated by accounts with department-restricted access to identify potential exploitation attempts.
- Temporarily restrict access to '/admin/sys/user/' endpoints if administrative functions cannot be verified for all assigned 'sys:user:*' administrators.
