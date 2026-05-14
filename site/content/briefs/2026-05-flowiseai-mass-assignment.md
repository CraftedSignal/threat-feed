---
title: FlowiseAI Mass Assignment Vulnerability in Tool Update Endpoint
slug: 2026-05-flowiseai-mass-assignment
description: A mass assignment vulnerability exists in the tool update endpoint of FlowiseAI, allowing authenticated users to modify server-controlled properties like workspaceId, createdDate, and updatedDate when updating a tool resource, leading to cross-workspace reassignment and unauthorized metadata modification, breaking tenant isolation in versions 3.1.1 and earlier.
date: "2026-05-14T14:53:10Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - mass-assignment
  - tenant-isolation
  - flowiseai
  - cve-2026-42862
vendors:
  - FlowiseAI
products:
  - flowise (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Network Drive
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: Indicator Removal on Host
references:
  - https://github.com/advisories/GHSA-x5v6-pj28-cwwm
  - CVE-2026-42862
rules:
  - title: Detect FlowiseAI Mass Assignment in Tool Update Endpoint
    description: Detects CVE-2026-42862 exploitation — modification of server-controlled properties in FlowiseAI tool update endpoint.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
  - title: Detect FlowiseAI Tool Update with Modified Date
    description: Detects CVE-2026-42862 exploitation — Detects updates to FlowiseAI tool via the API where the create or update date is modified.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
rules_count: 2
---

FlowiseAI versions 3.1.1 and earlier contain a mass assignment vulnerability in the tool update endpoint. This flaw allows authenticated users to modify server-controlled properties of tool resources via the `PUT /api/v1/tools/{toolId}` endpoint. Due to a lack of server-side validation and authorization checks, attackers can manipulate fields such as `workspaceId`, `createdDate`, and `updatedDate`. Successful exploitation can lead to unauthorized cross-workspace reassignment of tools and modification of tool metadata, posing a significant risk to multi-tenant environments where tenant isolation is critical. This vulnerability is identified as CVE-2026-42862.

## Attack Chain

1. An attacker authenticates to the FlowiseAI interface.
2. The attacker captures a legitimate request to update a tool via the `PUT /api/v1/tools/{toolId}` endpoint.
3. The attacker modifies the captured request body by injecting additional, server-controlled fields like `workspaceId`, `createdDate`, and `updatedDate` with attacker-controlled values.
4. The attacker sends the modified request to the `/api/v1/tools/{toolId}` endpoint.
5. The FlowiseAI server, lacking proper validation, accepts the injected fields and persists them to the database.
6. The tool's `workspaceId` is updated to the attacker's specified value, reassigning it to a different workspace.
7. The tool's `createdDate` and `updatedDate` metadata are modified to the attacker's specified values.
8. The attacker successfully moves tools between workspaces without authorization, violating tenant isolation boundaries.

## Impact

Successful exploitation of this vulnerability, CVE-2026-42862, allows authenticated users to manipulate internal attributes of tool resources within FlowiseAI. This includes the ability to reassign tools to arbitrary workspaces, potentially granting unauthorized access to sensitive resources in multi-tenant deployments. Modification of metadata fields like `createdDate` and `updatedDate` can further complicate auditing and forensic investigations. The vulnerability affects FlowiseAI versions 3.1.1 and earlier.

## Recommendation

*   Apply the latest security patches or upgrade to a version of FlowiseAI that addresses CVE-2026-42862.
*   Implement server-side validation and authorization checks on the `PUT /api/v1/tools/{toolId}` endpoint to prevent modification of server-controlled properties.
*   Deploy the Sigma rule "Detect FlowiseAI Mass Assignment in Tool Update Endpoint" to identify potential exploitation attempts in real-time.
*   Monitor web server logs for suspicious PUT requests to the `/api/v1/tools` endpoint with unexpected parameters to identify unauthorized attempts to modify server-controlled properties.
*   Regularly audit tool assignments and metadata to detect any unauthorized changes.
