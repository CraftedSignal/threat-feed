---
brief_id: brief-2026-10-22-pyjwt-hmac-bypass
event_id: brief-2026-10-22-pyjwt-hmac-bypass
revision: 1
activity_at: "2026-10-22T20:04:19Z"
title: 'PyJWT: Token forgery via empty HMAC key in JWK/JWKS (GHSA-pxh4-856f-4h89)'
slug: 2026-10-pyjwt-hmac-bypass
description: PyJWT fails to validate empty HMAC keys when resolving from JWK or JWKS, allowing unauthenticated attackers to forge JWTs with arbitrary claims when the identity provider is misconfigured.
date: "2026-10-22T20:04:19Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
products:
  - PyJWT (<= 2.13.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: This occurs when the signing secret is sourced from an unset environment variable / unset config row / key-finder fallback that base64url-encodes b"" into the published JWKS.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-pxh4-856f-4h89
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory applications utilizing PyJWT PyJWKClient for JWKS key resolution
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects PyJWK, PyJWKSet, and PyJWKClient
  mitigation_plan:
    - priority: immediate
      action: Upgrade PyJWT to the latest patched version
      owner: IT Operations
      addresses: PyJWT (<= 2.13.0)
      evidence: GHSA-pxh4-856f-4h89 resolution
---

PyJWT versions up to 2.13.0 contain a vulnerability where `HMACAlgorithm.from_jwk` fails to reject empty symmetric keys (`kty=oct` with `k=""`). An attacker can forge JWTs signed with an empty HMAC key and bypass authentication if the target application resolves its signing keys from a JWK or JWKS source that publishes an empty key - a scenario typically triggered by an unset environment variable in the authentication service. This defect mirrors previously patched vulnerabilities in other JWT libraries and exposes an asymmetric verification gap compared to the existing hardened string-secret API.

## Attack Chain

1. An authentication service is misconfigured (e.g., `SIGNING_SECRET` is unset), resulting in a published JWKS containing an oct-type key with an empty `k` value.
2. The target application uses `PyJWKClient` to resolve signing keys from the published JWKS.
3. An attacker crafts a JWT with arbitrary claims (e.g., `role:admin`) and selects the target JWK via the `kid` header.
4. The attacker signs the forged token locally using an empty byte string as the HMAC key.
5. The attacker sends the forged token in the `Authorization` header to the target application.
6. The target application fetches the empty-key JWK, which `PyJWKClient` processes into a zero-length key.
7. The application invokes `jwt.decode` using the zero-length key, which `HMACAlgorithm` accepts, verifying the forged signature and granting the attacker unauthorized access.

## Impact

Successful exploitation allows unauthenticated attackers to achieve full impersonation and privilege escalation by minting tokens with arbitrary claims. This affects any application using `PyJWK`, `PyJWKSet`, or `PyJWKClient` for key resolution.

## Recommendation

1. Upgrade `PyJWT` to a version containing the fix for GHSA-pxh4-856f-4h89.
2. Audit authentication provider configurations to ensure that signing secrets are correctly populated and not defaulting to empty strings.
3. Validate that published JWKS endpoints do not contain entries with empty `k` values.
4. If an immediate upgrade is not possible, implement a validation layer in the application to reject `PyJWK` objects resolved with empty keys before passing them to `jwt.decode`.
