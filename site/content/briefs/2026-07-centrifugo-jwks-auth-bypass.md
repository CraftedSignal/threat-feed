---
title: Centrifugo JWKS Cache Authentication Bypass
slug: 2026-07-centrifugo-jwks-auth-bypass
description: A critical authentication bypass vulnerability exists in Centrifugo v6's dynamic JWKS endpoint feature, allowing an attacker to bypass JWT authentication for one tenant by leveraging a valid token from another tenant due to incorrect JWKS key caching indexed only by the `kid`.
date: "2026-07-03T12:28:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - jwt
  - jwks
  - centrifugo
  - web-application
vendors:
  - Centrifugal
products:
  - Centrifugo v6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker who can obtain or mint a valid token for issuer/tenant A
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: This is a cross-issuer / cross-tenant JWT authentication bypass in dynamic JWKS deployments. This affects connection token verification and subscription token verification because both paths use the same JWKS verification manager.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g6vg-wj8f-48cj
---

A severe authentication bypass vulnerability affects Centrifugo v6, a real-time messaging server, specifically within its dynamic JSON Web Key Set (JWKS) endpoint feature. This flaw, not yet assigned a CVE, enables an attacker to gain unauthorized access to one tenant's resources by exploiting a valid token from a separate, distinct tenant. The vulnerability stems from Centrifugo's JWKS key cache and `singleflight` mechanism, which are keyed solely by the `kid` (key ID) value from a JWT header, rather than a combination of the `kid` and the resolved JWKS endpoint, issuer, or audience. This design oversight means that if an attacker can ensure their issuer's key, sharing a `kid` with another target tenant, is cached first, they can forge JWTs for users within the target tenant. This leads to unauthorized connection and subscription token acceptance, posing a significant risk to multi-tenant Centrifugo deployments using dynamic JWKS configurations.

## Attack Chain

1.  **Initial Token Acquisition**: An attacker obtains or mints a valid JWT for an authorized issuer/tenant (e.g., Tenant A) with a specific `kid` value in its header. This JWT is signed by Tenant A's private key.
2.  **Cache Priming (Tenant A)**: The attacker presents Tenant A's valid JWT to the Centrifugo server, triggering the dynamic JWKS endpoint to fetch Tenant A's public key corresponding to the JWT's `kid`. This public key is then stored in Centrifugo's JWKS cache, indexed only by the `kid`.
3.  **Token Forgery (Tenant B)**: The attacker crafts a new JWT, claiming to be a user in a different target issuer/tenant (e.g., Tenant B), but importantly, uses the *same `kid`* value in the header and signs it with *Tenant A's private key*.
4.  **Forged Token Presentation**: The attacker presents this forged Tenant B JWT to the Centrifugo server for authentication (e.g., connection or subscription verification).
5.  **Vulnerable Cache Lookup**: Centrifugo attempts to verify the forged Tenant B JWT. When performing the JWKS key lookup, it queries its cache using only the `kid` from the forged token.
6.  **Cross-Tenant Key Reuse**: Because the `kid` matches the key previously cached for Tenant A, Centrifugo retrieves and uses Tenant A's public key (instead of Tenant B's intended key) to verify the forged Tenant B token.
7.  **Authentication Bypass**: Since the forged token was signed by Tenant A's private key and verified by Tenant A's public key (due to the cache hit), the verification succeeds, granting the attacker unauthorized access as the claimed user in Tenant B.
8.  **Impact**: The attacker achieves unauthorized connection or subscription to Tenant B's services, leading to data exposure, unauthorized actions, and compromise of integrity or confidentiality within the target tenant.

## Impact

This vulnerability results in a cross-issuer/cross-tenant JWT authentication bypass in Centrifugo deployments configured to use dynamic JWKS endpoints. The primary impact is unauthorized access, allowing an attacker who can acquire or forge a token for one tenant to impersonate users in another tenant if both share a `kid` value and the attacker's key is cached first. This directly compromises the integrity of connection and subscription token verification. Consequences include unauthorized user authentication within a different namespace and potential cross-tenant confidentiality and integrity breaches, as the server incorrectly trusts tokens across isolated trust domains, particularly in multi-tenant environments where `iss` or `aud` claims are used to derive dynamic JWKS URLs.

## Recommendation

*   **Patch Centrifugo**: Immediately apply any available patches or updates from the vendor (Centrifugal) that address this JWKS caching vulnerability.
*   **Review JWKS Configuration**: Reconfigure Centrifugo to avoid dynamic JWKS endpoint templates that rely solely on `kid` for key identification across different trust domains, if a patch is not immediately available.
*   **Audit JWKS `kid` Usage**: Review all JWKS documents for Centrifugo deployments to ensure that `kid` values are unique across all potential issuer/audience configurations, if dynamic JWKS is used.
*   **Segment Multi-Tenant Environments**: Implement network and logical segmentation between tenants to limit the blast radius in case of a successful authentication bypass.
