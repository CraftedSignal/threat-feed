---
title: Oxia Bearer Token Exposure in Debug Logs
slug: 2024-01-09-oxia-token-leak
description: Oxia exposes the full bearer token, including JWT header, payload, and signature, in debug log messages when OIDC authentication fails, allowing attackers with log access to replay the tokens.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oxia
  - jwt
  - token leakage
  - credential access
vendors:
  - Oxia
products:
  - Oxia
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://github.com/advisories/GHSA-pm7q-rjjx-979p
rules:
  - title: Detect Oxia Token Leak in Logs
    description: Detects instances where Oxia logs a full bearer token during authentication failures, indicating a potential token leakage vulnerability.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
  - title: Detect Failed OIDC Authentication Attempts in Oxia
    description: Detects failed OIDC authentication attempts in Oxia based on log messages.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Oxia, a distributed database, is vulnerable to exposing sensitive bearer tokens in its debug logs. Specifically, when OpenID Connect (OIDC) authentication fails, the complete JWT, including header, payload, and signature, is logged in plaintext at the DEBUG level. This occurs in versions 0.16.1 and earlier. If debug logging is enabled in production environments, these tokens are written to application logs and potentially any connected log aggregation systems. An attacker gaining access to these logs could then extract valid JWT tokens and use them to impersonate legitimate users. The vulnerability stems from the `validateTokenWithContext()` function within `oxiad/common/rpc/auth/interceptor.go`. Defenders should ensure that debug logging is disabled in production or implement detections to identify potential token leakage.

## Attack Chain

1.  A user attempts to authenticate to an Oxia service using OIDC.
2.  The `validateTokenWithContext()` function in `oxiad/common/rpc/auth/interceptor.go` is invoked to validate the provided JWT token.
3.  If the token validation fails, the complete token is logged at DEBUG level using `slog.String("token", token)`.
4.  The debug logs containing the full bearer token are written to the application log files.
5.  An attacker gains unauthorized access to the application log files or the connected log aggregation system.
6.  The attacker extracts valid JWT tokens from the compromised logs.
7.  The attacker replays the extracted JWT token to authenticate as a legitimate user.
8.  The attacker gains unauthorized access to Oxia resources and data, performing actions as the compromised user.

## Impact

The exposure of bearer tokens can lead to unauthorized access to Oxia resources. An attacker with access to application logs can extract valid JWT tokens and impersonate legitimate users. The impact depends on the privileges associated with the compromised user account. This vulnerability affects all Oxia deployments using OIDC authentication with debug logging enabled in production, potentially impacting a large number of users and sensitive data stored within the database.

## Recommendation

*   Ensure DEBUG-level logging is never enabled in production environments as a primary mitigation step ([Workarounds](#workarounds)).
*   Deploy the Sigma rule to detect instances of failed authentication attempts where the full bearer token is logged, and investigate immediately ([Sigma rule: Detect Oxia Token Leak in Logs]).
*   Upgrade to a patched version of Oxia that redacts the token in log output, preserving only the last 8 characters.
*   Review and harden access controls for application logs and log aggregation systems to prevent unauthorized access.
