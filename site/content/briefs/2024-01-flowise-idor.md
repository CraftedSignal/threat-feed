---
title: Flowise DocumentStore IDOR Vulnerability
slug: 2024-01-flowise-idor
description: A mass assignment vulnerability in the DocumentStore creation endpoint of Flowise allows authenticated users to control the primary key (id) and internal state fields of DocumentStore entities. By exploiting the implicit UPSERT operation, an attacker can overwrite existing DocumentStore objects, potentially leading to cross-workspace object takeover and broken object-level authorization (IDOR) in multi-tenant deployments.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - mass-assignment
  - flowise
  - vulnerability
vendors:
  - Flowise
products:
  - Flowise
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1212
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-3prp-9gf7-4rxx
rules:
  - title: Flowise DocumentStore Update via POST
    description: Detects POST requests to the DocumentStore endpoint that attempt to update an existing object by specifying an existing 'id'.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Flowise DocumentStore Mass Assignment Attempt
    description: Detects POST requests to DocumentStore endpoint with multiple parameters that could be used for mass assignment
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Flowise versions 3.0.13 and earlier contain a mass assignment vulnerability in the DocumentStore creation endpoint. This flaw stems from the application's use of `repository.save()` with a client-supplied primary key ('id'), effectively turning the POST create endpoint into an implicit UPSERT (update or insert) operation. An authenticated attacker, particularly in multi-tenant environments, can exploit this by manipulating the 'id' parameter to overwrite existing DocumentStore objects, potentially leading to cross-workspace object takeover and broken object-level authorization (IDOR). This allows unauthorized modification or reassignment of DocumentStore objects belonging to other workspaces, affecting data indexing, retrieval, and AI workflow execution. This vulnerability was published on 2026-04-17T21:34:16Z.

## Attack Chain

1. An attacker authenticates to a Flowise instance.
2. The attacker identifies a valid DocumentStore UUID belonging to another workspace (Workspace A), either through enumeration or prior knowledge.
3. The attacker crafts a malicious POST request to `/api/v1/document-store` with a JSON payload.
4. The JSON payload includes the `id` parameter set to the known UUID from Workspace A, along with other parameters like `name` and `description` containing attacker-controlled values.
5. The Flowise server receives the POST request and, due to the missing input validation, maps the entire request body directly to the DocumentStore entity.
6. The `repo.save(documentStore)` function is called. Because the provided `id` already exists, TypeORM performs an UPDATE operation on the existing DocumentStore record in Workspace A.
7. The attacker-supplied values overwrite the existing DocumentStore's attributes (e.g., name, description), and potentially workspaceId.
8. If workspaceId is overwritten, the DocumentStore is effectively reassigned to the attacker's workspace, leading to object takeover.

## Impact

Successful exploitation allows an attacker to perform mass assignment on server-managed fields, overwrite existing objects via UPSERT, and achieve Broken Object Level Authorization (BOLA). In multi-tenant Flowise deployments, this can result in cross-workspace object takeover, where an attacker can modify or reassign DocumentStore objects belonging to other tenants. Since DocumentStore objects manage crucial configurations like embedding providers and vector store settings, a successful takeover can compromise data indexing, retrieval processes, and overall AI workflow execution.

## Recommendation

*   Deploy the following Sigma rule to detect suspicious POST requests to the `/api/v1/document-store` endpoint that attempt to modify existing DocumentStore objects by specifying an existing `id` (Sigma rule: Flowise DocumentStore Update via POST).
*   Implement server-side validation and authorization checks on the DocumentStore creation endpoint to prevent mass assignment and ensure that users can only modify DocumentStore objects within their own workspace. Specifically, implement a DTO allowlist or field filtering before persistence as mentioned in the overview.
*   Upgrade Flowise to a version beyond 3.0.13 or apply the necessary patches to remediate the vulnerability (Affected Packages: npm/flowise (vulnerable: <= 3.0.13)).
*   Implement logging and monitoring of API calls to detect unauthorized attempts to access or modify DocumentStore objects across workspaces.
*   Review and enforce proper workspace scoping in all service functions that retrieve DocumentStore entities by id to mitigate the risk of IDOR.
