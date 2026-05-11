---
title: Unity Catalog JWT Issuer Validation Bypass Allows User Impersonation (CVE-2026-27478)
slug: 2026-05-unity-catalog-jwt-bypass
description: A critical authentication bypass vulnerability exists in the Unity Catalog token exchange endpoint (CVE-2026-27478), allowing attackers to impersonate any user by forging JWTs with a self-controlled issuer and exchanging them for valid access tokens, granting unauthorized access to catalogs and other resources.
date: "2026-05-11T17:59:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:unitycatalog:unitycatalog:*:*:*:*:data:*:*:*
tags:
  - authentication-bypass
  - jwt
  - unity-catalog
vendors:
  - Databricks
products:
  - unitycatalog-server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-27478
    cvss: 9.1
    epss: 0.00023
references:
  - https://github.com/advisories/GHSA-qqcj-rghw-829x
  - CVE-2026-27478
rules:
  - title: Detect Unity Catalog JWT Issuer Validation Bypass Attempt
    description: Detects attempts to exploit CVE-2026-27478 by monitoring POST requests to the token exchange endpoint with JWTs potentially signed by untrusted issuers.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1550.002
    data_sources:
      - webserver
rules_count: 1
---

A critical authentication bypass vulnerability, tracked as CVE-2026-27478, has been identified in the token exchange endpoint (`/api/1.0/unity-control/auth/tokens`) of Unity Catalog. This vulnerability allows an attacker to completely impersonate any user within the system. The issue arises because the endpoint dynamically fetches the JWKS (JSON Web Key Set) for signature validation based on the issuer (`iss`) claim in incoming JWTs without validating whether the issuer is a trusted identity provider. Additionally, the implementation does not validate the audience (`aud`) claim, enabling tokens intended for other services to be used. This bypass has been observed in unitycatalog-server versions 0.4.0 and earlier. Successful exploitation grants unauthorized access to all catalogs, schemas, tables, and other resources accessible to the impersonated user.

## Attack Chain

1.  The attacker sets up their own OIDC-compliant server. This server needs to have a valid JWKS endpoint, serving the public key.
2.  The attacker generates an RSA key pair and creates a JWKS containing the public key.
3.  The attacker crafts a malicious JWT. The `iss` claim is set to the attacker's OIDC server URL. The `sub` and `email` claims are set to the email address of the target user in Unity Catalog. The `aud` claim is optionally set to a value other than "unity-catalog".
4.  The crafted JWT is signed with the attacker's private key, using the RS256 algorithm and including the key ID (`kid`) in the header.
5.  The attacker sends a POST request to the Unity Catalog token exchange endpoint (`/api/1.0/unity-control/auth/tokens`).
6.  The request includes the `grant_type` set to `urn:ietf:params:oauth:grant-type:token-exchange`, the `requested_token_type` set to `urn:ietf:params:oauth:token-type:access_token`, the `subject_token_type` set to `urn:ietf:params:oauth:token-type:id_token`, and the `subject_token` set to the crafted JWT.
7.  The Unity Catalog server retrieves the JWKS from the attacker's OIDC server based on the `iss` claim. It then validates the JWT signature using the public key from the JWKS.
8.  Due to the lack of issuer validation, the server trusts the attacker's JWT and exchanges it for a valid internal access token, effectively impersonating the target user, and allowing unauthorized access to Unity Catalog resources.

## Impact

Successful exploitation of CVE-2026-27478 allows an attacker to completely impersonate any user within the Unity Catalog system. This grants the attacker unauthorized access to all catalogs, schemas, tables, and other resources that the impersonated user has permissions to access. The vulnerability affects unitycatalog-server versions 0.4.0 and earlier, potentially impacting all organizations using these vulnerable versions. Data breaches, unauthorized data modification, and complete compromise of the Unity Catalog system are potential outcomes.

## Recommendation

*   Upgrade `maven/io.unitycatalog:unitycatalog-server` to a version later than 0.4.0 to remediate CVE-2026-27478.
*   Monitor network traffic for POST requests to `/api/1.0/unity-control/auth/tokens` with suspicious `subject_token` values, using the Sigma rule `Detect Unity Catalog JWT Issuer Validation Bypass Attempt`.
*   Implement strict validation of the `iss` claim in JWTs at the token exchange endpoint to ensure that only trusted identity providers are allowed.
