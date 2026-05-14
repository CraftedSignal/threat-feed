---
title: FlowiseAI CustomTemplate Mass Assignment Allows Cross-Workspace Template Takeover
slug: 2026-05-flowise-template-takeover
description: FlowiseAI is vulnerable to cross-workspace data takeover due to mass assignment in the CustomTemplate controller, allowing an attacker to move templates to other workspaces by overwriting the `workspaceId` via API request.
date: "2026-05-14T16:24:30Z"
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
  - Flowise <= 3.1.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-728h-4mwj-f2p4
rules:
  - title: Detect Flowise CustomTemplate WorkspaceId Modification
    description: Detects modification of the workspaceId field in CustomTemplate update requests, indicating a potential cross-workspace data takeover attempt
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Flowise CustomTemplate Create with WorkspaceId
    description: Detects creation of a CustomTemplate with a specified workspaceId, which can be an attempt to bypass workspace isolation.
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

FlowiseAI versions 3.1.1 and earlier are vulnerable to a mass assignment vulnerability in the CustomTemplate controller (`packages/server/src/services/marketplaces/index.ts`). This flaw allows an authenticated attacker to modify the `workspaceId` of a custom template through an API request, effectively moving the template to another workspace. The vulnerability stems from the use of `Object.assign(entity, body)` without proper input validation, enabling the client to control critical fields like `workspaceId` and `id`. This issue poses a significant threat as it breaks workspace isolation and allows unauthorized access to custom templates. The vulnerability was identified and a fix has been suggested via allowlisting in PR https://github.com/FlowiseAI/Flowise/pull/6129.

## Attack Chain

1.  Attacker, authenticated to workspace A, obtains a valid session cookie/JWT for the Flowise web UI.
2.  Attacker identifies or creates a custom template within workspace A and notes its entity `id`.
3.  Attacker crafts a `PUT /api/v1/customtemplates/<id>` request, including a JSON body with the target workspace B's UUID in the `"workspaceId"` field (e.g., `"workspaceId": "<workspace-B-id>"`).
4.  The server receives the request and calls `Object.assign(updateEntity, body)`, copying the attacker-supplied `workspaceId` into the entity.
5.  The updated entity, now associated with workspace B, is persisted to the database.
6.  The custom template is now accessible to members of workspace B and can be modified or used by them.
7.  The attacker from workspace A loses access to the template, as it is no longer associated with their workspace.
8.  Workspace A's audit logs do not reflect any unauthorized activity, as the operation appears as a normal template update.

## Impact

This vulnerability allows any authenticated user to violate workspace boundaries, potentially exposing sensitive workflow templates to unauthorized users. An attacker can move a customtemplate to any workspace whose UUID they can enumerate, which is made trivial due to workspace UUIDs being exposed in API responses. Successful exploitation allows unauthorized access, modification, and usage of custom templates, potentially leading to data leaks or other malicious activities.

## Recommendation

*   Upgrade to a version of FlowiseAI that includes the fix from PR https://github.com/FlowiseAI/Flowise/pull/6129, which implements an allowlist pattern.
*   Implement regression tests as described in the advisory to prevent future regressions that could reintroduce mass assignment vulnerabilities in CustomTemplate creation and update paths.
*   Deploy the Sigma rule `Detect Flowise CustomTemplate WorkspaceId Modification` to detect potential exploitation attempts by monitoring API requests to the `/api/v1/customtemplates/<id>` endpoint with a modified `workspaceId` in the request body.
*   Enable webserver logging to facilitate the detection of malicious HTTP requests.
