---
title: Race Condition in free5GC AUSF Authentication Context
slug: 2026-08-free5gc-ausf-race
description: An authentication state race condition in free5GC AUSF allows an attacker to perform a targeted denial-of-service by overwriting authentication contexts keyed by SUPI, preventing successful subscriber authentication.
date: "2026-08-29T03:13:51Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:free5gc:ausf:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - free5gc
  - 5g-security
vendors:
  - free5GC
products:
  - AUSF (<= 1.4.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The confirmed impact is targeted denial of authentication service for a chosen SUPI.
    confidence_band: high
cves:
  - id: CVE-2026-55784
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-334q-h5g3-fpxv
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55784
action_plan:
  priority: elevated
  owners:
    - Infrastructure Security
    - Telecom Operations
  immediate_actions:
    - action: Upgrade free5GC AUSF components to a patched version.
      owner: IT Operations
      due: 72h
      evidence: Source provides confirmed vulnerable versions and remediation guidance.
  mitigation_plan:
    - priority: immediate
      action: Enforce SBI access controls including mTLS and OAuth2.
      owner: Network Engineering
      addresses: Lack of SBI isolation
      evidence: Source recommends enforcing OAuth2/mTLS for SBI access in production.
---

The free5GC AUSF component (v1.4.4 and earlier) is vulnerable to a race condition that allows an attacker to selectively disrupt 5G authentication procedures for specific subscribers. The vulnerability stems from the use of a global `sync.Map` to store `AusfUeContext` objects, where the subscriber's Permanent Identifier (SUPI) serves as the sole lookup key. The implementation lacks logic to detect concurrent authentication sessions for the same subscriber, allowing subsequent requests to unconditionally overwrite existing contexts.

An attacker with network-level access to the Service Based Architecture (SBA) or the SBI/N12 interface can flood the AUSF with concurrent `POST /nausf-auth/v1/ue-authentications` requests for a targeted SUPI. By replacing the active authentication context mid-procedure, the attacker ensures that the legitimate EAP-AKA' response from the user is validated against mismatched session material (specifically `K_aut` and `XRES`). This causes integrity check failures and prevents the subscriber from completing authentication, effectively denying the service to the target.

## Attack Chain

1. The legitimate subscriber initiates a 5G authentication procedure.
2. The AUSF processes the initial request and stores the authentication context (`ctx_LEGIT`) in the global `UePool` map under the target's SUPI key.
3. The attacker identifies a target SUPI/SUCI and initiates a flood of concurrent `POST /nausf-auth/v1/ue-authentications` requests for that same identity.
4. Each malicious request causes the AUSF to overwrite the previous entry in the `UePool` map with a new context (`ctx_ATTACK`).
5. The target subscriber receives an authentication challenge and computes a valid EAP-AKA' response based on `ctx_LEGIT`.
6. The subscriber transmits the response to the AUSF `/eap-session` endpoint.
7. The AUSF retrieves the current (overwritten) context (`ctx_ATTACK`) from the map.
8. The integrity check (AT_MAC verification) fails because the response was signed using parameters from `ctx_LEGIT` while the AUSF validates against `ctx_ATTACK`, resulting in a service denial.

## Impact

Successful exploitation results in a targeted denial of authentication service for any selected subscriber in a 5G network running vulnerable versions of free5GC. While the AUSF service remains operational and no sensitive authentication material is leaked, the impacted subscriber is unable to connect to the network as long as the attacker maintains the request flood. The scope of impact is limited to those with direct or proxied access to the AUSF internal SBI/N12 interface.

## Recommendation

1. Upgrade free5GC AUSF to a version that addresses the context management vulnerability (patch status for v1.4.4+).
2. Implement a unique session identifier in the `AusfUeContext` and ensure authentication state lookups use this identifier rather than the SUPI.
3. Deploy logic to check for ongoing authentication procedures for a specific SUPI and reject concurrent attempts with `HTTP 409 Conflict`.
4. Enforce strict mTLS and OAuth2 requirements on all internal SBI traffic to prevent unauthorized access to the AUSF interface.
5. Enable rate limiting on authentication request endpoints to mitigate the impact of flooding attacks.
