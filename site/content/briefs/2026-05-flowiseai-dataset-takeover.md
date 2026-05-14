---
title: FlowiseAI Cross-Workspace Dataset Takeover via Mass Assignment
slug: 2026-05-flowiseai-dataset-takeover
description: FlowiseAI is vulnerable to a mass assignment vulnerability via `Object.assign(entity, body)` which allows a client-controlled `workspaceId` to be overwritten on the Dataset entity, leading to cross-workspace data takeover and IDOR.
date: "2026-05-14T16:24:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass-assignment
  - cross-workspace
  - idor
  - flowiseai
vendors:
  - FlowiseAI
products:
  - flowise (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Media
references:
  - https://github.com/advisories/GHSA-5h9v-837x-m97r
rules:
  - title: Detect FlowiseAI Dataset WorkspaceID Update
    description: Detects attempts to update a FlowiseAI dataset's workspaceId, indicating potential cross-workspace data takeover. This rule identifies PUT requests to the datasets endpoint that include the workspaceId parameter.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect FlowiseAI Dataset ID Update Attempt
    description: Detects attempts to modify a FlowiseAI dataset's id via API, indicating potential IDOR or mass assignment exploitation. This rule identifies PUT requests to the datasets endpoint that include the id parameter.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI versions 3.1.1 and earlier contain a mass assignment vulnerability in the Dataset service, allowing authenticated users to move datasets between workspaces. The vulnerability stems from the use of `Object.assign()` to copy request body parameters directly into Dataset entities without proper input validation or sanitization. Specifically, the `workspaceId` field can be overwritten by a malicious user, leading to unauthorized access and data exposure in the target workspace. The root cause mirrors a previously patched vulnerability in the `DocumentStore` service, indicating a systemic issue with input handling across the application. This flaw can be exploited by any authenticated user with permission to update a dataset.

## Attack Chain

1. An attacker authenticates to FlowiseAI within workspace A, obtaining a valid session cookie or JWT.
2. The attacker identifies a dataset within workspace A that they have permission to update.
3. The attacker crafts a malicious API request (PUT `/api/v1/datasets/<id>`) to update the target dataset.
4. The request body includes a `workspaceId` parameter set to the UUID of a different workspace (workspace B).
5. The server-side Dataset controller uses `Object.assign(updateEntity, body)` to update the dataset entity, blindly accepting the malicious `workspaceId`.
6. The persistence layer commits the changes to the database, updating the `workspaceId` of the dataset.
7. The dataset is now associated with workspace B, granting access to members of workspace B.
8. The attacker in workspace A loses access to the dataset, effectively transferring ownership.

## Impact

This vulnerability allows any authenticated user to move datasets from one workspace to another, leading to unauthorized data access and potential data breaches. Datasets contain training and evaluation data, which may include sensitive information. Successful exploitation allows unauthorized access to this data in the destination workspace, and removes access from the original owner. Given that workspace UUIDs can be enumerated via the API, the impact is significant.

## Recommendation

*   Apply the patch from PR https://github.com/FlowiseAI/Flowise/pull/6051 which implements an allowlist pattern.
*   Implement regression tests to ensure that attempts to modify `workspaceId`, `id`, `createdDate`, or `updatedDate` fields via API requests are rejected or ignored (see suggested fix in content).
*   Deploy the Sigma rule below to detect suspicious updates to dataset entities with modified `workspaceId` values.
*   Implement input validation on all API endpoints that modify Dataset entities to prevent mass assignment vulnerabilities.
