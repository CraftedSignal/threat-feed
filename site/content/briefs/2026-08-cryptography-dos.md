---
title: Resource Exhaustion in Python cryptography Certificate Chain Validation
slug: 2026-08-cryptography-dos
description: An exponential complexity vulnerability in the certificate chain validation logic of the Python cryptography library allows for denial-of-service attacks via resource exhaustion using crafted, redundant certificate chains.
date: "2026-08-03T23:41:42Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - cryptography (<= 48.0.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker-controlled certificate chain can lead the processing to easily take more than 5s to reject in testing.
    confidence_band: high
cves:
  - id: CVE-2026-69249
references:
  - https://github.com/advisories/GHSA-jwv3-5hgf-82ww
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-69249
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Patch the cryptography library dependency in all deployed environments to version 48.0.1 or higher.
      owner: IT Operations
      due: 72h
      evidence: Source states remediation involves tracking valid issuers to skip seen ones, provided in version 48.0.0+ patches.
  mitigation_plan:
    - priority: immediate
      action: Implement timeouts for any certificate verification processes handling untrusted user input.
      owner: Application Security
      addresses: CVE-2026-69249
      evidence: Source shows timeout > 5s during DoS conditions.
---

The Python cryptography library (versions <= 48.0.0) contains a resource exhaustion vulnerability (CVE-2026-69249) within its certificate chain validation logic. The internal function `build_chain_inner` fails to implement de-duplication when analyzing potential certificate issuers during recursive path building. An attacker can craft a malicious certificate chain containing redundant, self-signed certificates, which forces the validation engine to re-process the same candidates multiple times. This recursion leads to exponential processing time increases, causing significant CPU and memory consumption. While the implementation enforces a maximum chain depth to ensure termination, the amplification factor is sufficient to exceed typical timeouts (e.g., 5 seconds), facilitating a denial-of-service (DoS) attack against applications that process untrusted certificate input. This issue does not compromise the cryptographic integrity or validity of processed certificates, but it degrades service availability for any system relying on this library for certificate chain validation.

## Attack Chain

1. The attacker generates a malicious certificate chain containing multiple duplicate, self-signed intermediate certificates.
2. The attacker delivers the crafted certificate chain to an application that utilizes the `cryptography` library for TLS or certificate verification.
3. The application passes the untrusted chain to the `PolicyBuilder.build_server_verifier` or a similar verification interface.
4. The `build_chain_inner` function begins recursive validation of the provided certificates.
5. The validation engine encounters the duplicate self-signed certificates but lacks logic to track or skip already-analyzed candidates.
6. The recursive calls to `build_chain_inner` exponentially multiply as the engine attempts to resolve redundant paths through the same set of certificates.
7. The process consumes high CPU cycles and memory over several seconds, effectively blocking the application thread from performing legitimate tasks.
8. The application hits a latency threshold or resource limit, resulting in a denial-of-service state for that verification process.

## Impact

Successful exploitation results in a localized denial-of-service for any process invoking the certificate validation routines. This vulnerability targets a fundamental component used in various networking and security products, potentially impacting any sector that parses user-supplied certificate chains. While this does not permit unauthorized access or data exfiltration, the potential for service disruption is significant for high-traffic infrastructure.

## Recommendation

* Update the Python cryptography library to a patched version (fixed in versions after 48.0.0) to implement the required candidate de-duplication logic in `build_chain_inner`.
* Audit applications that perform certificate chain validation on untrusted input to ensure they implement timeouts or rate-limiting for the validation logic.
* Monitor application logs for high-latency certificate validation events that correlate with large numbers of certificate inputs (CVE-2026-69249).
