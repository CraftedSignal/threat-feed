---
title: FlowiseAI Evaluator Cross-Workspace Takeover via Mass Assignment
slug: 2026-05-flowiseai-evaluator-takeover
description: FlowiseAI is vulnerable to a mass assignment vulnerability in the Evaluator controller/service, where an attacker can manipulate the `workspaceId` during evaluator creation or updates, leading to cross-workspace data takeover and IDOR.
date: "2026-05-14T16:23:34Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - mass-assignment
  - idor
  - privilege-escalation
  - cloud
vendors:
  - FlowiseAI
products:
  - flowise <= 3.1.1
  - FlowiseAI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-wxrr-jp8m-qq7f
rules:
  - title: Detect FlowiseAI Evaluator WorkspaceId Manipulation via API
    description: Detects attempts to manipulate the `workspaceId` of an evaluator entity in FlowiseAI via API requests, indicating a potential cross-workspace takeover attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect FlowiseAI Evaluator ID Manipulation via API
    description: Detects attempts to manipulate the `id` of an evaluator entity in FlowiseAI via API requests, indicating a potential IDOR attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI versions 3.1.1 and earlier are susceptible to a mass assignment vulnerability within the Evaluator entity. This flaw arises from the Evaluator controller/service's use of `Object.assign(entity, body)` without proper input validation, allowing client-controlled parameters such as `workspaceId`, `id`, `createdDate`, and `updatedDate` to be injected via API requests. An attacker, authenticated within one workspace, can leverage this vulnerability to move Evaluator entities—and potentially sensitive scoring rubrics—to other workspaces. This can result in unauthorized access to data, privilege escalation, and a loss of data ownership. This issue is similar to a previously patched vulnerability in the `DocumentStore` (commit 840d2ae), indicating a systemic pattern of insecure object assignment within the application.

## Attack Chain

1.  The attacker authenticates to the FlowiseAI web UI as a member of workspace A, obtaining a valid session cookie or JWT.
2.  The attacker creates or identifies an existing Evaluator entity within workspace A.
3.  The attacker crafts a malicious `PUT` request to the `/api/v1/evaluators/<id>` endpoint (or equivalent) targeting the Evaluator entity identified in the previous step.
4.  The attacker includes a JSON body within the `PUT` request, specifically setting the `workspaceId` parameter to the UUID of a different workspace (workspace B).
5.  The FlowiseAI server receives the request and, due to the mass assignment vulnerability, uses `Object.assign(updateEntity, body)` to update the Evaluator entity, overwriting its `workspaceId` with the attacker-supplied value.
6.  The persistence layer commits the changes to the database, effectively transferring ownership of the Evaluator entity to workspace B.
7.  Members of workspace B can now access, modify, and utilize the transferred Evaluator entity.
8.  The attacker's workspace A loses access to the Evaluator, and no suspicious activity is logged in workspace A's audit logs, masking the malicious action.

## Impact

This vulnerability allows any authenticated user with permission to update an evaluator to move it to any workspace. The impact of a successful attack includes unauthorized access to evaluators and their scoring rubrics by members of the target workspace, data exfiltration, and potential privilege escalation. An attacker can enumerate workspace UUIDs via the `/api/v1/workspaces` API listing or through other API responses, making it trivial to identify valid target workspaces.

## Recommendation

*   Upgrade FlowiseAI to version 3.1.2 or later, where the fix from pull request #6050 has been applied.
*   Deploy the Sigma rule "Detect FlowiseAI Evaluator WorkspaceId Manipulation via API" to identify attempts to exploit this vulnerability by monitoring API requests that modify the `workspaceId` parameter.
*   Implement regression tests to verify that attempts to modify `workspaceId`, `id`, `createdDate`, or `updatedDate` via API requests are rejected or ignored by the server.
*   Apply the allowlist pattern to all controllers that handle entity updates to prevent similar mass assignment vulnerabilities.
