---
title: FlowiseAI Mass Assignment Vulnerability in Variable Update Endpoint
slug: 2026-05-flowise-mass-assignment
description: FlowiseAI versions 3.1.1 and earlier contain a mass assignment vulnerability in the variable update endpoint allowing authenticated users to modify server-controlled properties like workspaceId, createdDate, and updatedDate, potentially breaking tenant isolation in multi-workspace environments (CVE-2026-42861).
date: "2026-05-14T14:53:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mass assignment
  - tenant isolation
  - web application
vendors:
  - FlowiseAI
products:
  - flowise <= 3.1.1
references:
  - https://github.com/advisories/GHSA-6fw7-3q8r-m5vj
  - CVE-2026-42861
rules:
  - title: Detect FlowiseAI Mass Assignment in Variable Update
    description: Detects attempts to exploit the FlowiseAI mass assignment vulnerability (CVE-2026-42861) by monitoring PUT requests to the variable update endpoint with modifications to restricted fields.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect FlowiseAI suspicious date manipulation
    description: Detects attempts to exploit CVE-2026-42861 by looking for unusual dates in the updatedDate and createdDate fields. Requires webserver logs.
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

FlowiseAI, a low-code platform for building AI workflows, is vulnerable to a mass assignment flaw (CVE-2026-42861) affecting versions 3.1.1 and earlier.  The vulnerability resides in the `/api/v1/variables/{variableId}` endpoint, which is used for updating variable resources. Due to missing server-side validation, an authenticated attacker can modify critical, server-controlled properties such as `workspaceId`, `createdDate`, and `updatedDate`. This can lead to unauthorized cross-workspace reassignment of variables, potentially compromising tenant isolation in multi-tenant environments. The issue was reported in May 2026, and defenders need to implement mitigations to prevent unauthorized data access and manipulation.

## Attack Chain

1.  Attacker authenticates to FlowiseAI with valid user credentials.
2.  Attacker identifies a target variable ID within the application they wish to manipulate.
3.  Attacker crafts a malicious PUT request to `/api/v1/variables/{variableId}`.
4.  The request body includes the `workspaceId` field, setting it to the ID of a different workspace the attacker wishes to access.
5.  The request body may also include modified `createdDate` and `updatedDate` values for the variable.
6.  The FlowiseAI server, lacking proper validation, accepts the attacker-supplied `workspaceId`, `createdDate`, and `updatedDate` values.
7.  The server updates the variable in the database with the attacker-controlled values, effectively reassigning the variable to the attacker's chosen workspace.
8.  The attacker can now access and potentially manipulate resources within the targeted workspace using the reassigned variable.

## Impact

Successful exploitation allows authenticated users to manipulate internal variable attributes, potentially leading to cross-workspace reassignment of variables, unauthorized modification of metadata, and tenant isolation bypass in multi-workspace deployments. This can allow an attacker to move variables between workspaces without proper authorization. The vulnerability affects FlowiseAI installations version 3.1.1 and earlier.

## Recommendation

*   Apply input validation and authorization checks on the `/api/v1/variables/{variableId}` endpoint to prevent modification of server-controlled properties like `workspaceId`, `createdDate`, and `updatedDate` as described in CVE-2026-42861.
*   Monitor PUT requests to the `/api/v1/variables/{variableId}` endpoint for attempts to modify the `workspaceId` parameter to detect potential exploitation attempts. Use the detection rule `Detect FlowiseAI Mass Assignment in Variable Update` to identify anomalous requests.
*   Implement workspace access controls and verify that users can only access variables within their assigned workspace, regardless of the `workspaceId` attribute.
