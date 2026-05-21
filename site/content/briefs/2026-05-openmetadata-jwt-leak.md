---
title: OpenMetadata TEST_CONNECTION Workflow Leaks JWT and Database Password
slug: 2026-05-openmetadata-jwt-leak
description: OpenMetadata version 1.12.1 is vulnerable to an information disclosure issue where a non-admin user can trigger a TEST_CONNECTION workflow for a Database Service and receive the cleartext database password and the ingestion bot JWT in the HTTP response, enabling privilege escalation.
date: "2026-05-21T16:37:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openmetadata
  - information-disclosure
  - jwt-leak
  - credential-access
vendors:
  - OpenMetadata
products:
  - openmetadata-service (< 1.12.4)
  - OpenMetadata 1.12.1
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-9vmh-whc4-7phg
  - CVE-2026-46481
rules:
  - title: Detect OpenMetadata TEST_CONNECTION Workflow Password Leak
    description: Detects CVE-2026-46481 exploitation — cleartext password exposure in OpenMetadata TEST_CONNECTION workflow responses.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect OpenMetadata Ingestion Bot JWT Leak
    description: Detects CVE-2026-46481 exploitation — Ingestion bot JWT exposure in OpenMetadata workflow responses.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1550.002
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

OpenMetadata version 1.12.1 is vulnerable to an information disclosure vulnerability where a non-admin SSO user can trigger a `TEST_CONNECTION` workflow for a Database Service. The HTTP 201 response to the `POST /api/v1/automations/workflows` request inadvertently includes both the cleartext database password within `request.connection.config.password` and the ingestion bot JWT within `openMetadataServerConnection.securityConfig.jwtToken`. This vulnerability allows an attacker to obtain sensitive credentials and impersonate the ingestion bot. The leaked JWT can be reused to access sensitive APIs, such as `GET /api/v1/services/databaseServices/{id}?include=all`, effectively granting bot-level privileges to unauthorized users. This issue differs from GHSA-pqqf-7hxm-rj5r as it specifically affects the `automations/workflows` TEST_CONNECTION endpoint.

## Attack Chain

1. An authenticated SSO user with access to the OpenMetadata UI navigates to a Database Service.
2. The user opens the connection tab of the Database Service and initiates the "Test connection" action.
3. The UI sends a `POST` request to `/api/v1/automations/workflows` with a JSON payload containing connection details. The password field in the request is masked.
4. The OpenMetadata server responds with an HTTP 201 status code, including the cleartext database password in the `request.connection.config.password` field of the response body.
5. The server response also includes a valid JWT for the `ingestion-bot` account in the `openMetadataServerConnection.securityConfig.jwtToken` field.
6. The attacker extracts the leaked ingestion-bot JWT from the server response.
7. The attacker reuses the leaked JWT in the `Authorization` header of subsequent API requests.
8. The attacker sends a `GET` request to `/api/v1/services/databaseServices/{id}?include=all` to retrieve the full database service details, including the username and password, confirming bot-level access.

## Impact

Successful exploitation of this vulnerability allows any user capable of running the "Test connection" workflow to recover both the database credentials in cleartext and a long-lived ingestion-bot JWT. This enables the attacker to act as the ingestion-bot, gaining unauthorized access to modify services and metadata within the OpenMetadata system. The severity is high, because successful credential access allows immediate escalation of privileges.

## Recommendation

*   Upgrade OpenMetadata to version 1.12.4 or later to patch CVE-2026-46481.
*   Deploy the Sigma rule "Detect OpenMetadata TEST_CONNECTION Workflow Password Leak" to identify attempts to exploit this vulnerability by monitoring for HTTP 201 responses from the /api/v1/automations/workflows endpoint that include password information.
*   Rotate all ingestion-bot JWTs to invalidate any previously leaked tokens.
*   Implement proper secret management using the Secrets Store, ensuring sensitive information is not exposed in API responses.
