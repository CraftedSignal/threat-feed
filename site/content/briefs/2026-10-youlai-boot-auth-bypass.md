---
title: 'CVE-2026-110215: Privilege Escalation in youlai-boot via Missing Authorization'
slug: 2026-10-youlai-boot-auth-bypass
description: An authenticated low-privileged user can exploit a missing authorization vulnerability in youlai-boot to assign administrative permissions to their own role and elevate privileges.
date: "2026-10-14T04:38:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:youlai:youlai_boot:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - rbac-bypass
vendors:
  - youlai
products:
  - youlai-boot (<= 2.21.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated low-privileged user can leverage the PUT /api/v1/roles/{roleId}/menus endpoint to assign arbitrary permissions to their own role and force a refresh of the Redis permission cache, effectively granting themselves administrative access.
    confidence_band: high
cves:
  - id: CVE-2026-110215
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110215
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade youlai-boot to version 2.21.2 or later to address CVE-2026-110215
      owner: IT Operations
      due: 24h
      evidence: youlai-boot through 2.21.1 contains a missing authorization vulnerability
  hunt_leads:
    - lead: Identify suspicious PUT requests to /api/v1/roles/*/menus from non-administrative user sessions.
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PUT /api/v1/roles/{roleId}/menus endpoint is the vector for exploitation
  mitigation_plan:
    - priority: immediate
      action: Upgrade youlai-boot to 2.21.2 or later
      owner: IT Operations
      addresses: CVE-2026-110215
      evidence: NVD report identifies affected version range through 2.21.1
---

CVE-2026-110215 describes a missing authorization vulnerability in youlai-boot versions up to 2.21.1. The flaw resides within the role permission management API, specifically the PUT /api/v1/roles/{roleId}/menus endpoint. An authenticated user, including low-privileged accounts such as a test or guest account, can interact with this endpoint to arbitrarily modify permissions assigned to specific roles. By assigning administrative menu and button permissions to their own role and triggering a refresh of the Redis-backed permission cache, an attacker can effectively escalate their privileges to administrator-equivalent access. This vulnerability poses a significant risk to organizations relying on youlai-boot for role-based access control (RBAC), as it allows for trivial bypass of intended security boundaries within the application.

## Impact

Successful exploitation of CVE-2026-110215 results in complete privilege escalation within the youlai-boot application. An attacker with minimal user privileges can grant themselves full administrative control, enabling unauthorized access to sensitive data, administrative features, and management of other user accounts. This compromises the integrity and confidentiality of the entire application environment.

## Recommendation

Prioritized actions for security and IT teams:

- Upgrade youlai-boot to a version later than 2.21.1 immediately to patch the authorization flaw.
- Audit access logs for the PUT /api/v1/roles/{roleId}/menus endpoint to identify potentially unauthorized role permission modifications.
- Review all current role and permission assignments within the application for discrepancies or signs of unauthorized elevation.
- Enforce strict monitoring on sensitive API endpoints that modify application-level access controls.
