---
title: Flowise Unauthenticated OAuth 2.0 Access Token Disclosure
slug: 2024-01-09-flowise-oauth-disclosure
description: Flowise versions 3.0.13 and earlier contain an authentication bypass vulnerability that allows an unauthenticated attacker to obtain OAuth 2.0 access tokens associated with a public chatflow.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - flowise
  - oauth2
  - authentication-bypass
  - credential-access
vendors:
  - Flowise
products:
  - Flowise
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-6f7g-v4pp-r667
rules:
  - title: Detect Unauthenticated Public Chatbot Config Access
    description: Detects unauthenticated access to the public chatbot configuration endpoint in Flowise, which could indicate an attempt to retrieve OAuth credential identifiers.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthenticated OAuth2 Credential Refresh
    description: Detects unauthenticated requests to refresh OAuth2 credentials in Flowise. Successful exploitation leads to unauthorized access token retrieval.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Flowise is vulnerable to unauthenticated OAuth 2.0 access token disclosure in versions 3.0.13 and earlier. The vulnerability stems from the exposure of internal `flowData` via the `/api/v1/public-chatbotConfig/<chatflowId>` endpoint, which includes OAuth credential identifiers. Subsequently, the `/api/v1/oauth2-credential/refresh/<credentialId>` endpoint allows OAuth 2.0 tokens to be refreshed without authentication. Combining these two weaknesses, an attacker can retrieve `chatflowId` values from public chatflows and then obtain valid OAuth 2.0 access tokens without authentication, potentially leading to unauthorized data access and account compromise. This issue affects self-hosted Flowise deployments because public chatflows are designed for unauthenticated access.

## Attack Chain

1. The attacker identifies a self-hosted Flowise instance running a vulnerable version (<= 3.0.13).
2. The attacker accesses a public chatflow, obtaining the `chatflowId` from the URL, embedded widget, or browser network requests. Example: `d37b9812-72c1-4c64-b152-665f307f755e`.
3. The attacker sends an unauthenticated GET request to `/api/v1/public-chatbotConfig/<chatflowId>` to retrieve the internal `flowData`.
4. The server responds with the `flowData`, which includes an OAuth credential identifier (`credential` field). Example: `"credential": "6efe0e20-ba6f-4fbb-9960-658feffa0542"`.
5. The attacker crafts an unauthenticated POST request to `/api/v1/oauth2-credential/refresh/<credentialId>`, using the obtained credential identifier.
6. The server, lacking authentication checks, refreshes the OAuth 2.0 token.
7. The server responds with valid OAuth 2.0 access token data, including an `access_token`.
8. The attacker uses the obtained OAuth 2.0 access token to access third-party services, potentially leading to unauthorized data access or account compromise.

## Impact

Successful exploitation allows an unauthenticated attacker to obtain OAuth 2.0 access tokens for third-party services configured within Flowise. This unauthorized access can result in data breaches, API abuse, or full account compromise on the third-party services. This is especially critical for self-hosted deployments where public chatflows are exposed to the internet. The number of affected instances is currently unknown, but any Flowise instance with public chatflows using OAuth 2.0 is potentially vulnerable.

## Recommendation

*   Upgrade Flowise to a version higher than 3.0.13 to patch the vulnerability.
*   Monitor web server logs for requests to `/api/v1/public-chatbotConfig/` and `/api/v1/oauth2-credential/refresh/` without prior authentication as indicated by the rule "Detect Unauthenticated OAuth2 Credential Refresh".
*   Implement rate limiting on the `/api/v1/oauth2-credential/refresh/` endpoint to mitigate potential abuse.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect exploitation attempts in real-time.
*   Review existing Flowise deployments for exposed public chatflows using OAuth 2.0 credentials.
