---
title: FlowiseAI Chatflow Update Endpoint Mass Assignment Vulnerability
slug: 2026-05-flowiseai-chatflow-mass-assignment
description: A mass assignment vulnerability exists in FlowiseAI's chatflow update endpoint (CVE-2026-42863), allowing authenticated users to modify server-controlled properties like `deployed`, `isPublic`, and `workspaceId` due to missing server-side validation, leading to cross-workspace resource reassignment and unauthorized modification of deployment and visibility settings.
date: "2026-05-14T14:55:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass-assignment
  - privilege-escalation
  - cross-workspace
  - flowiseai
vendors:
  - FlowiseAI
products:
  - flowise
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-5wxp-qjgq-fx6m
  - CVE-2026-42863
rules:
  - title: Detect FlowiseAI Chatflow Mass Assignment Attempt via API
    description: Detects CVE-2026-42863 exploitation — Attempts to modify restricted fields in FlowiseAI's chatflow update API endpoint, indicating a mass assignment vulnerability exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
  - title: Detect FlowiseAI Chatflow Mass Assignment Successful Modification
    description: Detects CVE-2026-42863 exploitation — Monitors successful modification of server-controlled fields. Requires correlation with other logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
rules_count: 2
---

A mass assignment vulnerability has been identified in FlowiseAI versions 3.1.1 and earlier. The vulnerability resides in the chatflow update endpoint, which lacks proper server-side validation and authorization checks. This allows authenticated users to manipulate server-controlled properties of chatflow objects, such as `deployed`, `isPublic`, and `workspaceId`, by including them in the request body. By exploiting this flaw, an attacker can reassign chatflows to different workspaces, modify deployment settings, and alter visibility settings, potentially leading to unauthorized access and control over resources in multi-tenant environments. This vulnerability is identified as CVE-2026-42863.

## Attack Chain

1. The attacker authenticates to the FlowiseAI interface with valid credentials.
2. The attacker captures a legitimate request used to update a chatflow object via the `PUT /api/v1/chatflows/{chatflowId}` endpoint.
3. The attacker modifies the captured request body to include server-controlled fields such as `deployed`, `isPublic`, and `workspaceId`.
4. The attacker sets the `workspaceId` to the ID of a workspace controlled by the attacker.
5. The attacker sends the crafted request to the `/api/v1/chatflows/{chatflowId}` endpoint.
6. The FlowiseAI server accepts the modified request and updates the chatflow object in the database without proper validation.
7. The chatflow is now reassigned to the attacker's workspace, granting the attacker unauthorized access.
8. The attacker can further modify the chatflow, change its visibility, or alter its deployment status.

## Impact

The mass assignment vulnerability in FlowiseAI allows authenticated users to manipulate server-controlled attributes of chatflows. This can result in unauthorized modification of chatflow visibility, deployment state changes, and cross-workspace reassignment of chatflows. In multi-tenant environments, this vulnerability breaks tenant isolation boundaries, enabling attackers to move chatflows between workspaces without authorization. Successful exploitation can lead to cross-workspace workflow takeover, unauthorized exposure of private workflows, and manipulation of deployed agent workflows, potentially affecting all FlowiseAI installations with versions 3.1.1 or lower.

## Recommendation

*   Deploy the Sigma rule "Detect FlowiseAI Chatflow Mass Assignment Attempt via API" to detect attempts to modify restricted fields via the chatflow update API endpoint.
*   Apply input validation to the `PUT /api/v1/chatflows/{chatflowId}` endpoint to prevent modification of `deployed`, `isPublic`, `workspaceId`, `createdDate`, `updatedDate`, `category`, and `type` parameters, mitigating CVE-2026-42863.
*   Upgrade FlowiseAI to a patched version that addresses the mass assignment vulnerability to prevent unauthorized modification of chatflow attributes, protecting against CVE-2026-42863.
