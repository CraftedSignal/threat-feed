---
title: Better Auth OAuth Provider Authorization Bypass Vulnerability
slug: 2026-04-better-auth-oauth-bypass
description: An authorization bypass vulnerability exists in Better Auth's OAuth provider, allowing low-privilege users to create OAuth clients despite configured clientPrivileges, potentially leading to unauthorized client registration and increased phishing risks.
date: "2026-04-17T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - oauth
  - authorization
  - bypass
  - privilege-escalation
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xr8f-h2gw-9xh6
rules:
  - title: Detect Unauthorized OAuth Client Creation Attempt
    description: Detects attempts to create OAuth clients by users lacking the necessary privileges based on POST requests to the create-client endpoint.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
      - linux
  - title: Detect OAuth Client Creation with Skip Consent
    description: Detects OAuth client creation requests with the skip_consent parameter, which may indicate an attempt to bypass user consent.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

An authorization bypass vulnerability affects the OAuth provider component of Better Auth, specifically versions 1.4.8-beta.7 through 1.6.4 and 1.7.0-beta.0 through 1.7.0-beta.1. This flaw allows any authenticated, low-privilege user to create OAuth clients, bypassing the intended restrictions set by the `clientPrivileges` configuration. The vulnerability stems from the client creation endpoints (`adminCreateOAuthClient` and `createOAuthClient`) not enforcing the `clientPrivileges` check before creating new OAuth clients. This bypass allows attackers to register OAuth clients with attacker-controlled redirect URIs and metadata, potentially leading to phishing attacks and abuse of trust assumptions in OAuth/OIDC flows. Defenders should implement detections to identify unauthorized OAuth client creation attempts.

## Attack Chain

1. An attacker authenticates to the Better Auth application with a low-privilege account.
2. The attacker crafts a POST request to either `/api/auth/oauth2/create-client` or a custom endpoint that routes to `adminCreateOAuthClient`.
3. The attacker includes parameters for `client_name`, `redirect_uris`, and other client metadata within the POST request body.
4. The `createOAuthClientEndpoint` function is called without first performing a `clientPrivileges` authorization check.
5. A new OAuth client is created and persisted in the system.
6. The attacker now controls a registered OAuth client with attacker-defined redirect URIs.
7. The attacker can potentially use this client for phishing attacks or to bypass consent flows if `skip_consent` is enabled (if `adminCreateOAuthClient` is exposed).
8. The attacker exploits the newly created OAuth client to gain unauthorized access to resources or user data.

## Impact

This vulnerability allows unauthorized users to create OAuth clients, potentially leading to several negative consequences. Attackers can register clients with malicious redirect URIs, which can be used in phishing campaigns to steal user credentials or OAuth tokens. In scenarios where the `adminCreateOAuthClient` endpoint is exposed, attackers can create clients that bypass user consent, further increasing the risk of successful attacks. The impact is significant because it breaks the intended access control mechanism of the `clientPrivileges` configuration, affecting applications that rely on it to restrict client registration. Successful exploitation can lead to unauthorized access to user data, compromised accounts, and damaged trust in the application.

## Recommendation

*   Monitor web server logs for POST requests to the `/api/auth/oauth2/create-client` endpoint, especially from users who should not have client creation privileges. Implement the "Detect Unauthorized OAuth Client Creation Attempt" Sigma rule below, using webserver logs (category: "webserver", product: "linux").
*   Apply the necessary patches to upgrade `@better-auth/oauth-provider` to a version that addresses this vulnerability (>= 1.6.5 or >= 1.7.0-beta.2).
*   Audit your application's OAuth client registration process to ensure that the `clientPrivileges` check is enforced correctly.
*   If using `adminCreateOAuthClient`, ensure it is not exposed to low-privilege authenticated users to prevent the `skip_consent` bypass.
*   Deploy the "Detect OAuth Client Creation with Skip Consent" Sigma rule if your deployment exposes the admin client creation endpoint.
