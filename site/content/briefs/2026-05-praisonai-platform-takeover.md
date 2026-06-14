---
title: Praison AI Platform Missing Authorization Leads to Workspace Takeover
slug: 2026-05-praisonai-platform-takeover
description: An authorization bypass vulnerability exists in praisonai-platform where any member can remove any other member, including the workspace owner, due to missing role checks and owner protection logic, allowing an attacker to lock the legitimate owner out of their own workspace, leading to a permanent denial-of-service and potential workspace takeover (CVE-2026-47409).
date: "2026-05-29T22:57:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - privilege-escalation
  - denial-of-service
vendors:
  - Praison AI
products:
  - praisonai-platform (<= 0.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1578
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-w388-2392-px73
  - CVE-2026-47409
rules:
  - title: Detect CVE-2026-47409 Exploitation - Unauthorized Member Removal
    description: Detects CVE-2026-47409 exploitation - attempts to remove workspace members via the API endpoint by non-admin users
    platform: sigma
    severity: high
    tactics:
      - cve-2026-47409
      - impact
      - privilege_escalation
    techniques:
      - T1578
    data_sources:
      - webserver
  - title: Detect CVE-2026-47409 Exploitation - Member Enumeration Before Removal
    description: Detects CVE-2026-47409 exploitation - identifying a DELETE request to the members endpoint preceded by a GET request to enumerate members, possibly targeting the owner.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-47409
      - discovery
      - privilege_escalation
    techniques:
      - T1087
    data_sources:
      - webserver
rules_count: 2
---

An authorization bypass vulnerability exists in the praisonai-platform version 0.1.2 and earlier. The vulnerability resides in the `DELETE /workspaces/{workspace_id}/members/{user_id}` endpoint. Due to insufficient access controls, any member of a workspace, regardless of their role, can remove any other member, including the workspace owner. This is because the endpoint is only gated by `require_workspace_member(workspace_id)` with a default `min_role="member"`. There is no caller-role check, no target-role check, and no protection against removing the last owner. This lack of proper authorization checks allows a malicious member to lock out the legitimate owner and potentially take over the workspace.

## Attack Chain

1. Attacker becomes a member of workspace `W` with the "member" role.
2. Attacker enumerates members of workspace `W` via `GET /workspaces/W/members` to discover the workspace owner's `user_id` (`O_id`).
3. Attacker sends a `DELETE /workspaces/W/members/O_id` request with their valid JWT.
4. The `require_workspace_member(W, attacker)` check passes, as the attacker is a member of the workspace.
5. `MemberService.remove(W, O_id)` is called, which removes the owner's member record from the database.
6. The owner attempts to access workspace resources, such as `GET /workspaces/W/...`, but `require_workspace_member(W, O_id)` now fails, resulting in a 403 error.
7. The legitimate owner is locked out of their own workspace.
8. The attacker can potentially combine this with other vulnerabilities (e.g., `update_member_role`, `delete_workspace`) to promote themselves to owner and/or completely wipe the workspace, further exacerbating the impact.

## Impact

Successful exploitation of this vulnerability allows any member of a workspace to remove any other member, including the workspace owner. This leads to a permanent denial-of-service for the legitimate owner, as they are locked out of their own workspace. An attacker can potentially gain full control of the workspace and its resources. This vulnerability is rated as sec-high, with a CVSS score of 8.1. Version 0.1.2 and earlier are affected.

## Recommendation

*   Apply the patch suggested in the advisory, specifically modifying `src/praisonai-platform/praisonai_platform/api/routes/workspaces.py` to include stricter role checks and owner protection logic.
*   Implement a detection rule to identify unauthorized attempts to remove workspace owners, focusing on `webserver` logs and the `DELETE /workspaces/{workspace_id}/members/{user_id}` endpoint (see Sigma rule below).
*   Review and harden other workspace-mutation endpoints to ensure proper authorization checks, as the advisory mentions similar vulnerabilities in companion endpoints.
