---
title: Authentication Bypass in fast-jwt via Unsigned JWT Processing
slug: 2026-10-fast-jwt-auth-bypass
description: The fast-jwt library (<= 6.3.0) fails to verify JWT signatures when the 'key' configuration is falsy and 'algorithms' are explicitly defined, allowing unauthenticated attackers to forge arbitrary claims.
date: "2026-10-09T07:58:42Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nearform:fast-jwt:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - jwt-vulnerability
  - software-supply-chain
vendors:
  - NearForm
products:
  - fast-jwt (<= 6.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker who can present a JWT to the application — regardless of algorithm — can forge arbitrary claims without possessing any signing key.
    confidence_band: high
cves:
  - id: CVE-2026-107720
    cvss: 7.4
references:
  - https://github.com/advisories/GHSA-8wpc-h4q6-8fxv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107720
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development
  immediate_actions:
    - action: Audit application code for fast-jwt implementation to ensure secret keys are not null or empty.
      owner: Development
      due: 24h
      evidence: Source document identifies the root cause as falsy key values.
  mitigation_plan:
    - priority: immediate
      action: Upgrade fast-jwt to 6.3.1 or later
      owner: Development
      addresses: CVE-2026-107720
      evidence: Source identifies CVE-2026-107720.
---

The fast-jwt library, version 6.3.0 and earlier, contains an authentication bypass vulnerability (CVE-2026-107720) in the `createVerifier` function. The vulnerability occurs due to incomplete signature verification logic when the secret `key` provided is either an empty string or `null`. If an application is configured with an explicit `algorithms` allowlist - a security practice - and the environment fails to provide a valid secret (e.g., an unset environment variable), the library skips the cryptographic signature check entirely.

This bypass allows an attacker to construct a JWT with arbitrary payloads and an empty signature, which the library will accept as valid. Because signature validation is bypassed, any payload data - such as user roles or administrative identifiers - is accepted by the application logic as trusted. This effectively grants an attacker full authentication or authorization bypass if they can present a JWT to the service.

## Attack Chain

1. Attacker identifies an application utilizing the `fast-jwt` library for authentication.
2. Attacker confirms the application is misconfigured due to a missing or empty secret key environment variable.
3. Attacker crafts a custom JWT header with a valid algorithm (e.g., "HS256") and a malicious payload.
4. Attacker sets the JWT signature portion to empty (trailing dot).
5. Attacker transmits the crafted, unsigned JWT to the target application endpoint.
6. The `createVerifier` logic detects the explicit `algorithms` setting and, due to the falsy key, bypasses the signature verification call.
7. The application processes the forged token, trusting the attacker-controlled claims (e.g., `admin: true`).

## Impact

Successful exploitation results in a full authentication and authorization bypass. Attackers can forge arbitrary claims within the JWT, potentially gaining unauthorized access to privileged user accounts or administrative functions. The impact is significant for any service relying on JWTs for session management that has unintentionally initialized with an empty secret key.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade `fast-jwt` to a version that addresses CVE-2026-107720 once available.
- Implement a check to ensure secret keys are not null or empty strings before initializing `createVerifier`.
- Validate that environment variables used as JWT secrets are properly populated during application startup.
- Patch CVE-2026-107720 by hardening the `createVerifier` logic to fail closed if the key is falsy regardless of the `algorithms` configuration.
