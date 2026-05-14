---
title: FlowiseAI DatasetRow Mass Assignment Allows Cross-Workspace Data Takeover
slug: 2026-05-flowiseai-datasetrow-takeover
description: FlowiseAI is vulnerable to a mass assignment vulnerability in the DatasetRow controller/service, allowing an authenticated attacker to overwrite the `workspaceId` and `id` of a DatasetRow entity, leading to cross-workspace data takeover and IDOR.
date: "2026-05-14T16:24:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass-assignment
  - idor
  - cross-workspace
vendors:
  - FlowiseAI
products:
  - flowise <= 3.1.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-7j65-65cr-6644
rules:
  - title: Detect FlowiseAI DatasetRow WorkspaceId Modification
    description: Detects attempts to modify the workspaceId parameter in FlowiseAI DatasetRow updates, indicating potential cross-workspace data takeover attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect FlowiseAI DatasetRow ID Modification
    description: Detects attempts to modify the id parameter in FlowiseAI DatasetRow updates, indicating potential IDOR attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI versions 3.1.1 and earlier contain a mass assignment vulnerability in the DatasetRow controller/service (`packages/server/src/services/dataset/index.ts`). The vulnerability arises from the use of `Object.assign(entity, body)` without an explicit field allowlist when creating or updating DatasetRow entities. This allows an attacker to control properties like `workspaceId` and `id` through the request body, leading to a cross-workspace data takeover. The vulnerability is similar to a previously patched issue in `DocumentStore` (commit 840d2ae), where an explicit field-by-field allowlist was implemented. This oversight enables an authenticated user to move DatasetRows, which contain individual training/evaluation records, between workspaces, potentially exposing sensitive data.

## Attack Chain

1. An attacker, authenticated as a member of workspace A, obtains a valid session cookie or JWT for the Flowise web UI.
2. The attacker creates a new DatasetRow within workspace A using the documented API (or reuses an existing one).
3. The attacker identifies the `id` of the DatasetRow they control.
4. The attacker sends a `PUT` request to the `/api/v1/datasetrows/<id>` endpoint (or an equivalent update endpoint).
5. The `PUT` request includes a JSON body containing `"workspaceId": "<workspace-B-id>"`, where `<workspace-B-id>` is the UUID of a different, arbitrary workspace.
6. The server-side controller receives the request and executes `Object.assign(updateEntity, body)`.
7. The `workspaceId` value from the request body overwrites the original `workspaceId` field of the `updateEntity`.
8. The persistence layer commits the modified row to the database, resulting in the DatasetRow being associated with workspace B. Members of workspace B can now access, modify, and utilize the transferred DatasetRow, while workspace A loses access.

## Impact

Successful exploitation allows any authenticated workspace member with the permission to update a DatasetRow to move it to any workspace. Since workspace UUIDs are exposed through API responses (e.g., `/api/v1/workspaces`), enumeration is trivial. This cross-workspace boundary violation exposes training/evaluation records contained in DatasetRows to unauthorized users. An attacker can also rebind a row to a Dataset in another workspace via `datasetId`, further exposing row content.

## Recommendation

*   Upgrade to FlowiseAI version 3.1.2 or later, where the fix from PR https://github.com/FlowiseAI/Flowise/pull/6051 has been applied, implementing an allowlist pattern.
*   Deploy the Sigma rule "Detect FlowiseAI DatasetRow WorkspaceId Modification" to detect attempts to modify the `workspaceId` parameter via the `/api/v1/datasetrows` endpoint.
*   Implement regression tests that assert requests containing `workspaceId`, `id`, `createdDate`, or `updatedDate` are rejected or do not change those columns on the persisted row for both create and update paths, as suggested in the overview.
*   Monitor web server logs for PUT requests to `/api/v1/datasetrows` with unusual parameters in the request body.
