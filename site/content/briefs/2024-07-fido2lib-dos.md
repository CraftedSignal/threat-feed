---
title: fido2-lib Denial-of-Service Vulnerability via CBOR Parsing
slug: 2024-07-fido2lib-dos
description: The fido2-lib library is vulnerable to a denial-of-service (DoS) attack due to a heap buffer over-read in the cbor-extract dependency when parsing CBOR attestation data, allowing an attacker to crash the server by sending a crafted CBOR payload during WebAuthn registration.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - fido2-lib
  - cbor-extract
  - denial-of-service
  - webauthn
vendors:
  - fido2-lib
products:
  - fido2-lib
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-g3qj-j598-cxmq
rules:
  - title: Detect Node.js Process Exit with SIGSEGV
    description: Detects Node.js processes exiting with a SIGSEGV signal (exit code 139), which can indicate a crash due to memory corruption vulnerabilities like the cbor-extract heap buffer over-read.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect CBOR-related process crashing with signal SIGSEGV
    description: Detects CBOR-related process crashing with signal SIGSEGV
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `fido2-lib` library, specifically versions 3.x, is susceptible to a denial-of-service (DoS) vulnerability due to a heap buffer over-read within its dependency, `cbor-extract`. This vulnerability arises during the parsing of CBOR (Concise Binary Object Representation) attestation data within the WebAuthn registration process. The root cause lies in the `cbor-extract` library (versions <= 2.2.0), which is optionally used by `cbor-x` (~1.6.0), a dependency of `fido2-lib`. A crafted 5-byte CBOR payload, when processed, triggers a `SIGSEGV` signal, causing the Node.js process to crash without any JavaScript exception handling. This issue was fixed in `cbor-extract@2.2.1` / `cbor-x@1.6.3` (released on 2026-03-08), but `fido2-lib@3.5.7` still pins `cbor-x` to a vulnerable version. This vulnerability is exploitable through a single, unauthenticated request to the WebAuthn registration endpoint.

## Attack Chain

1.  Attacker initiates a WebAuthn registration process on a vulnerable server.
2.  The server generates a challenge and sends it to the user's authenticator.
3.  Attacker intercepts the authenticator's registration response (containing the attestation object).
4.  Attacker replaces the original `attestationObject` in the response with a crafted 5-byte CBOR payload: `7a10000000`.
5.  Attacker sends the modified registration response to the server's registration verification endpoint via a POST request.
6.  The server calls the `attestationResult()` function in `fido2-lib` to verify the attestation.
7.  `attestationResult()` internally calls `cbor-x.decode()` to parse the `attestationObject`.
8.  `cbor-x.decode()` uses the vulnerable `cbor-extract` native addon, which calls `extractStrings()` during CBOR parsing, leading to a heap buffer over-read and a `SIGSEGV` signal, crashing the Node.js process. The attacker achieves denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, crashing the Node.js server. While the exact number of affected systems is unknown, any application using `fido2-lib` versions up to 3.5.7 with the `cbor-extract` native addon installed is vulnerable. This can impact any service relying on WebAuthn for authentication, including financial institutions, SaaS providers, and any application requiring strong authentication. A successful attack disrupts service availability and potentially exposes the organization to reputational damage.

## Recommendation

*   Upgrade the `cbor-x` dependency in `fido2-lib` to version 1.6.3 or higher to incorporate the fix for the heap buffer over-read, as described in the "Fix" section of this brief.
*   Monitor Node.js processes for unexpected exits with signal `SIGSEGV` (exit code 139) to detect potential exploitation attempts, using the process creation log source.
*   Implement rate limiting on the WebAuthn registration endpoint to mitigate the impact of potential DoS attacks.
