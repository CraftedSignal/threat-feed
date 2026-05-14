---
title: FlowiseAI Mass Assignment in Assistant Update Endpoint Allows Cross-Workspace Resource Reassignment
slug: 2026-05-flowiseai-mass-assignment
description: FlowiseAI version 3.1.1 and earlier contains a mass assignment vulnerability in the assistant update endpoint, allowing authenticated users to modify server-controlled properties like workspaceId, createdDate, and updatedDate, enabling cross-workspace reassignment of assistants and breaking tenant isolation in multi-workspace environments.
date: "2026-05-14T15:00:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass assignment
  - tenant isolation
  - flowiseai
  - web application
vendors:
  - FlowiseAI
products:
  - FlowiseAI (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-hp26-q66v-q2w7
rules:
  - title: Detect FlowiseAI Assistant WorkspaceId Manipulation
    description: Detects attempts to manipulate the workspaceId parameter in the FlowiseAI assistant update endpoint, indicating a potential cross-workspace reassignment attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect FlowiseAI Assistant Date Field Manipulation
    description: Detects attempts to manipulate the createdDate or updatedDate parameters in the FlowiseAI assistant update endpoint, indicating a potential metadata modification.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI version 3.1.1 and earlier is vulnerable to a mass assignment vulnerability in its assistant update endpoint. This vulnerability allows authenticated users to modify server-controlled properties, including workspaceId, createdDate, and updatedDate. By manipulating these properties, particularly the workspaceId, an attacker can reassign assistants to arbitrary workspaces. This poses a significant risk in multi-tenant deployments where tenant isolation is critical. The vulnerability arises due to missing server-side validation and authorization checks, allowing user-controlled request bodies to override internal, server-controlled properties. This can lead to unauthorized data access and modification across different workspaces.

## Attack Chain

1.  Attacker authenticates to the FlowiseAI interface with valid credentials.
2.  Attacker captures the HTTP request sent to update an assistant resource using the PUT `/api/v1/assistants/{assistantId}` endpoint.
3.  Attacker modifies the JSON request body to include the `workspaceId` parameter, setting it to the target workspace's ID.
4.  The attacker also injects `createdDate` and `updatedDate` parameters to control the assistant's metadata.
5.  Attacker sends the modified request to the `/api/v1/assistants/{assistantId}` endpoint.
6.  The server accepts the attacker-controlled `workspaceId`, `createdDate`, and `updatedDate` values without proper validation.
7.  The assistant resource is reassigned to the attacker-specified workspace, breaking tenant isolation.
8.  The attacker can now access and manipulate the reassigned assistant within the target workspace, potentially gaining unauthorized access to sensitive data.

## Impact

The mass assignment vulnerability in FlowiseAI allows authenticated users to perform unauthorized actions, including cross-workspace reassignment of assistants and modification of metadata. In multi-tenant deployments, this can lead to a complete breakdown of tenant isolation, allowing attackers to access and manipulate resources belonging to other tenants. The confirmed impacts include unauthorized modification of assistant metadata and cross-workspace data access. If successful, this can lead to data breaches, compliance violations, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Detect FlowiseAI Assistant WorkspaceId Manipulation` to detect attempts to modify the workspaceId parameter in the `/api/v1/assistants/{assistantId}` endpoint.
*   Deploy the Sigma rule `Detect FlowiseAI Assistant Date Field Manipulation` to detect attempts to modify the createdDate or updatedDate parameters in the `/api/v1/assistants/{assistantId}` endpoint.
*   Upgrade FlowiseAI to a version greater than 3.1.1 to remediate the mass assignment vulnerability.
