---
title: Incorrect Authorization in ProjectSend API
slug: 2026-10-projectsend-auth-bypass
description: ProjectSend versions prior to 2.7.0 are vulnerable to an authorization flaw allowing API token holders with management permissions to elevate privileges by modifying the token owner's credentials.
date: "2026-10-18T12:21:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:projectsend:projectsend:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - vulnerability
vendors:
  - ProjectSend
products:
  - ProjectSend (< 2.7.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Attackers with a token limited to manage_users and edit_users can set a new owner password, clear two-factor authentication, and sign in interactively with the owner's full role permissions.
    confidence_band: high
cves:
  - id: CVE-2026-112001
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112001
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade ProjectSend to 2.7.0 or later to patch CVE-2026-112001
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-112001 advisory
  mitigation_plan:
    - priority: immediate
      action: Review and restrict API token permissions to exclude manage_users and edit_users where possible
      owner: Security Operations
      addresses: CVE-2026-112001
      evidence: Source identifies token-based authorization as the root of the vulnerability
---

ProjectSend versions 2.0.0 through 2.6.x contain an incorrect authorization vulnerability (CVE-2026-112001) within the application's API. This vulnerability allows an attacker who possesses a valid API token with 'manage_users' and 'edit_users' permissions to perform unauthorized administrative actions. Specifically, the attacker can interact with the PATCH /api/v1/users/{user} endpoint to modify the password of the token owner. Furthermore, this exploit allows for the disabling of two-factor authentication (2FA) for that account. By performing these actions, the attacker can bypass security controls to gain interactive login access to the system, effectively inheriting the account's full role permissions. This flaw represents a significant risk for environments relying on ProjectSend for file management, as it enables lateral movement and privilege escalation for users with otherwise limited API-only access.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to escalate their privileges to match the owner of the API token. In scenarios where the token belongs to an administrator, this leads to full system compromise. The vulnerability affects all ProjectSend instances running versions prior to 2.7.0. If compromised, an attacker can exfiltrate sensitive files, modify system configurations, or create additional persistent accounts.

## Recommendation

- Upgrade all instances of ProjectSend to version 2.7.0 or later to remediate CVE-2026-112001.
- Audit existing API tokens to identify and revoke tokens with 'manage_users' or 'edit_users' permissions that are not strictly required for current integrations.
- Review web server access logs for anomalous PATCH requests targeting /api/v1/users/ endpoints.
