---
title: Authorization Omission in phpMyFAQ Group Permissions
slug: 2026-08-phpmyfaq-group-privesc
description: An authorization omission in phpMyFAQ's GroupController allows a delegated administrator to grant themselves arbitrary privileges by assigning unheld rights to a group they manage.
date: "2026-08-25T18:50:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - authorization-bypass
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An administrator with the GROUP_EDIT permission can grant arbitrary permissions to a group they belong to, including permissions they do not personally possess.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pg62-f8g4-4wqh
rules:
  - title: Detect Potential phpMyFAQ Privilege Escalation
    description: Detects POST requests to the GroupController updatePermissions endpoint which may indicate an attempt to escalate group privileges
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch phpMyFAQ to the latest available version
      owner: IT Operations
      due: 48h
      evidence: Vulnerability fixed in releases following 4.1.4
  hunt_leads:
    - lead: Audit access logs for excessive POST requests to /admin/group/update/permissions from non-SuperAdmin accounts
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Endpoint is the specific sink for privilege escalation
  mitigation_plan:
    - priority: immediate
      action: Review and audit all accounts currently holding the GROUP_EDIT permission
      owner: IT Operations
      addresses: Privilege Escalation via group management
      evidence: Attack requires an account with GROUP_EDIT to initiate escalation
---

phpMyFAQ contains an authorization omission vulnerability in the `GroupController::updatePermissions` endpoint (accessible via `POST /admin/group/update/permissions`). While the application previously hardened `UserController::updateUserRights` to prevent delegated administrators from assigning permissions they do not personally hold, this constraint was not applied to the equivalent group-rights endpoint. An attacker with the delegated `GROUP_EDIT` permission can modify the permissions of any group they control. By assigning high-privilege rights to a group of which they are a member, the attacker inherits those rights, enabling privilege escalation to full administrative access. This flaw affects phpMyFAQ versions up to and including 4.1.4.

## Attack Chain

1. Attacker gains access to a low-privilege administrative account granted the `GROUP_EDIT` permission.
2. Attacker logs into the phpMyFAQ administration interface.
3. Attacker identifies or gains membership in a group (G) they manage through their `GROUP_EDIT` authority.
4. Attacker constructs a `POST` request to `/admin/group/update/permissions` targeting group ID G.
5. Attacker includes `group_rights[]` parameters containing one or more high-privilege right IDs (e.g., user administration) that the attacker's account does not possess.
6. The `updatePermissions` controller verifies the attacker holds `GROUP_EDIT` but fails to validate that the attacker possesses the specific rights being granted.
7. The application updates the group's permission set in the `faqgroup_right` database table.
8. The attacker inherits the newly granted administrative rights through their membership in group G, resulting in full application-level compromise.

## Impact

Successful exploitation allows a delegated administrator (who is not a SuperAdmin) to escalate their privileges to any right within the application, including full administrative read/write/availability control. This bypasses the intended compartmentalization of administrative duties. The impact is critical to the integrity and confidentiality of the knowledge base managed by phpMyFAQ.

## Recommendation

Prioritize applying vendor-supplied patches for phpMyFAQ version 4.1.4 or newer. Until patching is possible, audit all accounts currently holding the `GROUP_EDIT` permission and restrict group membership for these accounts. Use the following webserver log monitoring to identify potential exploitation attempts.
