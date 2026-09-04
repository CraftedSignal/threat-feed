---
title: Semaphore UI Privilege Escalation via Custom Role Slug Collision
slug: 2026-09-semaphore-privilege-escalation
description: Semaphore UI is vulnerable to a privilege escalation where a project manager can create a colliding custom role slug to assign themselves owner-level permissions, bypassing access controls.
date: "2026-09-04T00:07:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:semaphoreui:semaphore:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - web-application
  - cve
vendors:
  - Semaphore
products:
  - Semaphore (< 0.0.0-20260705182501-bb2a4e1f08c8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A manager creates a role with slug 'manager' carrying the full bitmask '15'... and the manager's effective permissions become owner-equivalent.
    confidence_band: high
cves:
  - id: CVE-2026-73293
    cvss: 8.8
    epss: 0.00401
references:
  - https://github.com/advisories/GHSA-cxvf-gvfq-36w2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73293
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Semaphore UI to 0.0.0-20260705182501-bb2a4e1f08c8 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies version 0.0.0-20260705182501-bb2a4e1f08c8 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Monitor web logs for POST /api/project/*/roles for unauthorized slug creation.
      owner: SOC
      addresses: CVE-2026-73293
      evidence: Exploit requires interaction with the POST /api/project/{id}/roles endpoint.
---

Semaphore UI, a web-based automation platform, contains a critical privilege escalation vulnerability (CVE-2026-73293) in its custom project role management feature. A project member assigned the 'manager' role can escalate their privileges to those of a project owner by exploiting a slug collision vulnerability during the custom role creation process. The application's `ProjectMiddleware` incorrectly resolves effective permissions by prioritizing database role rows that match a user's assigned role slug. Because the API route `POST /api/project/{id}/roles` does not reserve built-in slug names (such as 'manager' or 'owner') or enforce a permission ceiling, a manager can create a custom role with the slug 'manager' and set the permission bitmask to the value of an owner. This flaw allows a malicious project manager to gain administrative control over the project, including the ability to change project settings, modify other project members, or demote the legitimate project owner.

## Attack Chain

1. The attacker is assigned the built-in 'manager' role within a target project.
2. The attacker authenticates to the Semaphore UI and confirms their current restricted permission state via `GET /api/project/{id}/role`.
3. The attacker crafts a `POST` request to `/api/project/{id}/roles` containing a JSON payload with `slug: "manager"` and `permissions: 15`.
4. The application processes the request, creating a new role row in the database with the colliding slug 'manager' and the elevated permission bitmask.
5. On the next API request, the `ProjectMiddleware` executes `GetProjectOrGlobalRoleBySlug`, which fetches the attacker-created role row.
6. The application overwrites the manager's effective permission bitmask with the elevated value from the database row.
7. The attacker performs previously unauthorized actions, such as `PUT /api/project/{id}` to modify project settings or `POST /api/project/{id}/users` to alter member access levels.

## Impact

Successful exploitation allows a project manager to effectively act as a project owner. This results in complete control over project resources, unauthorized access to sensitive project settings, the ability to remove or demote other users, and the potential for project deletion. This vulnerability affects instances utilizing the PRO build of Semaphore UI where custom project roles are active.

## Recommendation

Update Semaphore UI to version 0.0.0-20260705182501-bb2a4e1f08c8 or later to resolve CVE-2026-73293. For current deployments, monitor web server logs for `POST` requests to `/api/project/*/roles` from users with the 'manager' role that attempt to define reserved slugs such as 'manager', 'owner', 'task_runner', or 'guest'.
