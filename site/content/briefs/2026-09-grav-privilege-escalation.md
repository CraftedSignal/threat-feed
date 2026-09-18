---
title: Grav Privilege Escalation via Group Blueprint ACL Bypass
slug: 2026-09-grav-privilege-escalation
description: A missing 'security@' guard in Grav's group blueprint allows an 'admin.users' operator to escalate privileges to 'admin.super' by modifying group access configurations.
date: "2026-09-18T01:10:51Z"
lastmod: "2026-09-18T01:12:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - cms
  - vulnerability
  - web-application-vulnerability
  - path-traversal
  - cve-2026-74907
  - twig
  - security-misconfiguration
vendors:
  - getgrav
products:
  - Grav (<= 2.0.12)
  - grav (<= 2.0.14)
  - grav (<= 2.0.15)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'A delegated non-super operator holding admin.users.update can therefore save a group whose access map contains admin.super: true, which UserGroupObject::authorize then grants to every member of that group, a full privilege escalation to super-admin.'
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can achieve RCE, exfiltrate site data, or gain admin-equivalent control.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker crafts a malicious Twig template to execute unauthorized code or access sensitive data through the rendering engine.
    confidence_band: high
cves:
  - id: CVE-2026-75837
    cvss: 9.1
    epss: 0.00339
references:
  - https://github.com/advisories/GHSA-xhfv-7758-r9hx
  - CVE-2026-75837
  - https://github.com/advisories/GHSA-4v9q-p283-qc2m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74907
  - https://github.com/advisories/GHSA-3jhr-mxmx-38cx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76839
rules:
  - title: Detect CVE-2026-74907 Exploitation Attempt - Path Traversal
    description: Detects path traversal attempts targeting the Grav static asset server by looking for directory traversal sequences within requests to potential asset routes.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Grav to version 2.0.14 or later.
      owner: IT Operations
      due: 24h
      evidence: Source GHSA-xhfv-7758-r9hx fix recommendation
  hunt_leads:
    - lead: Look for POST requests to /admin/accounts/groups/ followed by manual changes in group permissions.
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PoC demonstrates a POST request to the group management endpoint to escalate privileges.
  mitigation_plan:
    - priority: immediate
      action: 'Manually patch system/blueprints/user/group.yaml by adding ''security@: admin.super'' to the access field if upgrading is delayed.'
      owner: IT Operations
      addresses: CVE-2026-75837
      evidence: Suggested fix from source advisory
updates:
  - at: "2026-09-18T01:11:02Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-74907 Exploitation Attempt - Path Traversal'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-4v9q-p283-qc2m
  - at: "2026-09-18T01:12:31Z"
    level: L1
    summary: added coverage for grav (<= 2.0.15)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-3jhr-mxmx-38cx
---

Grav version 2.0.12 and earlier contains a privilege escalation vulnerability within its Flex group management functionality. The core group blueprint file located at `system/blueprints/user/group.yaml` omits a mandatory `security@: admin.super` guard on the group access field. In the Grav Flex architecture, the `security@` guard is the primary mechanism that flags fields for exclusion during the data save path for non-super users.

Because this guard is missing from the group blueprint, a delegated administrator holding only `admin.users.update` permissions can successfully submit a request to update a group's access map. By injecting `admin.super: true` into the group's access configuration, the attacker effectively grants the 'super-admin' role to all members of that group. This escalation provides full administrative control over the application, including access to the scheduler, which can be leveraged for Remote Code Execution (RCE) via cron jobs, and potential Twig template evaluation.

## Attack Chain

1. Initial Access: The attacker authenticates as a user with `admin.users.update` permissions, which is typically granted to delegated administrators responsible for user management.
2. Discovery: The attacker identifies that they can modify group access configurations, as the application exposes groups at the `admin.users:crudl` path, which the attacker has permission to update.
3. Form Submission: The attacker sends a `POST` request to the `/admin/accounts/groups/` endpoint, embedding the malicious payload `access[admin][super]=true` within the group update data.
4. Blueprint Bypass: The system's `Blueprint::dynamicSecurity` check fails to flag the `access` field as restricted because the `group.yaml` blueprint lacks the required `security@: admin.super` declaration.
5. Validation Bypass: The `BlueprintSchema::filterArray` and `Validation::filterArray` logic processes the payload and retains the restricted `admin.super` key because the input is not marked for filtering.
6. Persistence: The application saves the unauthorized access configuration to `user://config/groups.yaml` via the `FlexObject::update()` path without further authorization checks.
7. Privilege Escalation: Upon the next request, the `UserGroupObject::authorize('admin.super')` method evaluates the modified group ACL and returns true, promoting the attacker to full super-admin status.
8. Impact: The attacker utilizes the escalated super-admin privileges to access the administrative dashboard, modify scheduler tasks, or execute malicious Twig templates to achieve RCE.

## Impact

Successful exploitation results in full administrative control (C:H/I:H/A:H) over the Grav instance. The attacker gains the ability to manage all users, execute arbitrary code via the scheduler, and modify system files. This vulnerability affects all Grav versions up to and including 2.0.12.

## Recommendation

Prioritized actions for security and IT operations teams:

- Update Grav to version 2.0.14 or later immediately to incorporate the required blueprint security guards.
- Audit existing `user://config/groups.yaml` files for any unauthorized `admin.super: true` entries in group access maps.
- Review all users currently holding the `admin.users` role to identify accounts that should not have the ability to modify group permissions.
- Use server-side web application logs to monitor for unauthorized `POST` requests to `/admin/accounts/groups/` originating from non-super-admin accounts.
