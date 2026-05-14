---
title: FlowiseAI Evaluation Cross-Workspace Data Takeover via Mass Assignment
slug: 2026-05-flowiseai-evaluation-takeover
description: FlowiseAI is vulnerable to a mass assignment vulnerability (fixed in PR 6050) that allows authenticated users to move Evaluation entities between workspaces by overwriting the `workspaceId` field via API request, leading to unauthorized data access.
date: "2026-05-14T16:23:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass-assignment
  - cross-workspace
  - privilege-escalation
vendors:
  - FlowiseAI
products:
  - flowise (<= 3.1.1)
  - FlowiseAI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Drive
references:
  - https://github.com/advisories/GHSA-mq53-pc65-wjc4
rules:
  - title: Detect FlowiseAI Evaluation WorkspaceId Manipulation
    description: Detects attempts to manipulate the `workspaceId` of an Evaluation entity by sending a PUT request to the `/api/v1/evaluations/<id>` endpoint with a JSON body that includes a `workspaceId` value.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect FlowiseAI Evaluation API Access
    description: Detects access to the FlowiseAI Evaluation API endpoints, which could be an indicator of exploitation attempts.
    platform: sigma
    severity: informational
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI, a low-code/no-code platform for building AI orchestration flows, is susceptible to a mass assignment vulnerability in versions 3.1.1 and earlier. The vulnerability resides within the Evaluation controller/service (`packages/server/src/services/evaluations/index.ts`). By exploiting this flaw, an authenticated user can manipulate the `workspaceId` of an Evaluation entity. This manipulation is possible due to the use of `Object.assign(entity, body)` without proper input validation, allowing an attacker to inject arbitrary `workspaceId` values into the request body. The vulnerability poses a significant risk as it enables cross-workspace data access and manipulation, potentially exposing sensitive information to unauthorized users. The root cause is similar to a previously patched vulnerability in `DocumentStore` (commit 840d2ae), indicating a pattern of insecure object assignment within the codebase.

## Attack Chain

1.  Attacker authenticates to FlowiseAI as a member of workspace A, obtaining a valid session cookie or JWT.
2.  Attacker identifies or creates an Evaluation entity within workspace A, noting its unique `id`.
3.  Attacker obtains the `workspaceId` of a target workspace B, potentially through API enumeration (e.g., `/api/v1/workspaces`) or by inspecting other entities' `workspaceId` fields.
4.  Attacker crafts a `PUT` request to the `/api/v1/evaluations/<id>` endpoint, using the `id` of the Evaluation entity from workspace A.
5.  The request body includes a JSON payload with the `"workspaceId"` field set to the `workspaceId` of workspace B.
6.  The server's Evaluation controller receives the request and uses `Object.assign(updateEntity, body)` to update the Evaluation entity. The attacker-controlled `workspaceId` overwrites the existing value.
7.  The persistence layer commits the changes to the database, associating the Evaluation entity with workspace B.
8.  The Evaluation entity is now accessible to members of workspace B and inaccessible to members of workspace A, resulting in unauthorized data access and potential modification.

## Impact

The vulnerability allows any authenticated user to move Evaluation entities between workspaces. This cross-workspace boundary violation allows an attacker to access and potentially modify evaluation runs, including captured prompts, model outputs, and scoring data, belonging to other workspaces. Successful exploitation leads to a high level of data exposure, as the attacker can exfiltrate or manipulate data that should be isolated to specific workspaces. The vulnerability affects FlowiseAI versions up to and including 3.1.1.

## Recommendation

*   Upgrade FlowiseAI to the latest version, which includes the fix from PR https://github.com/FlowiseAI/Flowise/pull/6050 that implements an allowlist pattern for updating Evaluation entities.
*   Deploy the Sigma rule `Detect FlowiseAI Evaluation WorkspaceId Manipulation` to identify potential exploitation attempts by monitoring PUT requests to the `/api/v1/evaluations/<id>` endpoint with modified `workspaceId` values.
*   Implement regression tests, as suggested in the source, to ensure that future code changes do not reintroduce the mass assignment vulnerability.
*   Consider implementing additional input validation on API endpoints to prevent similar mass assignment vulnerabilities in other parts of the application.
