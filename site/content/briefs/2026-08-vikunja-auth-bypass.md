---
title: Vikunja Improper Authorization via ProjectView Deletion
slug: 2026-08-vikunja-auth-bypass
description: An improper authorization vulnerability in Vikunja allows authenticated users to destroy task organization data in other projects by supplying a target view ID within a crafted API request.
date: "2026-08-28T21:18:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - web-application
  - data-destruction
vendors:
  - Vikunja
products:
  - Vikunja (all versions prior to patch)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attacker registers a local account on the target Vikunja instance.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1648
    technique_name: Serverless Execution
    evidence: The first scoped SQL statement fails silently because V does not belong to P_A.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-gg93-x632-9ccv
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Vikunja to the patched version.
      owner: IT Operations
      due: 24h
      evidence: Source provides patching guidance via GHSA.
  hunt_leads:
    - lead: Search web server access logs for DELETE requests to /projects/*/views/* where the project ID does not match the user context.
      technique_id: T1648
      data_needed:
        - webserver access logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The attack chain relies on specific API paths.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched Vikunja version.
      owner: IT Operations
      addresses: CWE-639
      evidence: Advisory confirms fix availability.
---

Vikunja contains an authorization bypass vulnerability (CWE-639) within the `ProjectView.Delete` method, which fails to properly validate that a requested view ID belongs to the project ID specified in the API path. Although the initial permission check correctly verifies that the user is an administrator of the provided project, the subsequent cascading delete operations on the `task_buckets` and `task_positions` tables are performed using only the view ID. Because the application does not verify the relationship between the project and the view during these cascading operations, an authenticated attacker can supply their own project ID while targeting a view ID belonging to a victim project. This results in the silent destruction of all Kanban bucket assignments and task orderings for the victim view, with no programmatic recovery path other than restoring from backups. The issue originates in `pkg/models/project_view.go` and affects all versions prior to the patch.

## Attack Chain

1. Attacker registers a local account on the target Vikunja instance (no special privileges required).
2. Attacker creates a new project via `PUT /api/v1/projects`, granting themselves Admin access to the new project ID (`P_A`).
3. Attacker identifies a victim Kanban view ID (`V`) by enumerating projects or observing API traffic.
4. Attacker constructs a malicious `DELETE` request: `DELETE /api/v1/projects/P_A/views/V`.
5. The application's `CanDelete` method validates the user is an admin of `P_A` and permits the request.
6. The `ProjectView.Delete` method executes the first scoped SQL statement, which fails silently because `V` does not belong to `P_A`.
7. The function proceeds to execute subsequent unscoped SQL `DELETE` statements on the `task_buckets` and `task_positions` tables using `V`.
8. All Kanban organization data for the victim view `V` is permanently deleted from the database.

## Impact

Successful exploitation results in the permanent loss of all task-to-bucket mappings and custom task ordering for the targeted Kanban view. This causes significant operational disruption for teams relying on Kanban boards, requiring manual reconfiguration or restoration from database backups. The vulnerability is highly accessible as it requires only standard user registration.

## Recommendation

1. Upgrade Vikunja immediately to the version containing the security patch that enforces project-view relationship validation within the `ProjectView.Delete` model method.
2. Implement strict input validation to verify that `view_id` maps to the `project_id` provided in the API request before any database modification occurs.
3. Ensure database backups are performed regularly and tested for restoration to mitigate the impact of data destruction vulnerabilities.
4. Review audit logs for `DELETE` operations on the `project_views` endpoint that target views not associated with the authenticated user's project ownership.
