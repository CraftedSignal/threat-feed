---
title: FlowiseAI Cross-Workspace Assistant Takeover via Mass Assignment
slug: 2026-05-flowiseai-workspace-takeover
description: FlowiseAI is vulnerable to a mass assignment vulnerability in the Assistant controller/service allowing an attacker, authenticated as a member of one workspace, to move an assistant (including configurations, instructions, tools and credentials) to another workspace by overwriting the `workspaceId` and `id` fields in the request body, leading to cross-workspace data takeover and IDOR.
date: "2026-05-14T16:24:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass-assignment
  - cross-workspace
  - flowiseai
vendors:
  - FlowiseAI
products:
  - flowise <= 3.1.1
references:
  - https://github.com/advisories/GHSA-78pr-c5x5-jggc
rules:
  - title: Detect FlowiseAI WorkspaceId Mass Assignment
    description: Detects attempts to modify the workspaceId via the /api/v1/assistants endpoint in FlowiseAI, indicating potential exploitation of the mass assignment vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect FlowiseAI Assistant ID Mass Assignment
    description: Detects attempts to modify the assistant ID via the /api/v1/assistants endpoint in FlowiseAI, potentially indicating exploitation of the mass assignment vulnerability.
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

FlowiseAI versions 3.1.1 and earlier are vulnerable to a mass assignment vulnerability in the Assistant controller located in `packages/server/src/services/assistants/index.ts`. An authenticated user can exploit this vulnerability to move an assistant, including its configuration, instructions, attached tools, and credentials, from one workspace to another. The vulnerability stems from the use of `Object.assign(entity, body)` without proper input validation, allowing a malicious actor to overwrite the `workspaceId` and `id` attributes of the Assistant entity. This issue is similar to a previously patched vulnerability in the `DocumentStore` (commit 840d2ae), highlighting a pattern of insecure mass assignment within the application. This vulnerability can lead to cross-workspace data access and privilege escalation.

## Attack Chain

1.  An attacker authenticates to FlowiseAI as a member of workspace A, obtaining a valid session cookie or JWT.
2.  The attacker creates (or reuses) an existing assistant within workspace A and notes the assistant's `id`.
3.  The attacker crafts a malicious `PUT` request to the `/api/v1/assistants/<id>` endpoint.
4.  The `PUT` request includes a JSON body containing a `workspaceId` attribute set to the UUID of workspace B (the target workspace).
5.  The FlowiseAI server receives the request and calls `Object.assign(updateEntity, body)` within the Assistant controller.
6.  The `workspaceId` in the request body overwrites the existing `workspaceId` of the assistant entity.
7.  The persistence layer updates the assistant record in the database, associating it with workspace B.
8.  The assistant is now accessible to members of workspace B, and the attacker in workspace A loses access.

## Impact

This vulnerability allows any authenticated user with permission to update an assistant to move it to another workspace, violating workspace isolation. Given that workspace UUIDs are easily enumerated via the API, an attacker can readily target specific workspaces. Successfully moving an assistant grants the destination workspace access to the assistant's configuration, instructions, attached tools, and credentials, potentially leading to unauthorized access to sensitive data and resources. This issue is classified as high severity because it breaks a fundamental security boundary within the application.

## Recommendation

*   Upgrade FlowiseAI to a version higher than 3.1.1 to incorporate the fix described in PR https://github.com/FlowiseAI/Flowise/pull/6128.
*   Deploy the Sigma rule `Detect FlowiseAI WorkspaceId Mass Assignment` to your SIEM to identify potential exploitation attempts.
*   Implement regression tests as described in the advisory to prevent future occurrences of this type of vulnerability; ensure requests containing `workspaceId`, `id`, `createdDate`, or `updatedDate` are rejected on both create and update paths.
