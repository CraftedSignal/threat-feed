---
title: Denial of Service Vulnerability in HAPI FHIR SHCParser
slug: 2026-09-hapi-fhir-dos
description: An infinite loop vulnerability in HAPI FHIR's SHCParser (CVE-2026-81876) allows attackers to cause resource exhaustion by submitting malformed or truncated DEFLATE-compressed Smart Health Card content.
date: "2026-09-18T01:11:43Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
vendors:
  - HL7
products:
  - org.hl7.fhir.r5 (<= 6.9.11)
  - org.hl7.fhir.validation (<= 6.9.11)
  - org.hl7.fhir.validation.cli (<= 6.9.11)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'A malformed Smart Health Card (SHC) JWT with zip: "DEF" and an empty or truncated DEFLATE payload causes SHCParser.inflate() to loop forever.'
    confidence_band: high
cves:
  - id: CVE-2026-81876
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-gq9c-wmrm-5hvr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81876
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade HAPI FHIR packages to version > 6.9.11
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-81876 advisory notes version 6.9.11 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Implement request timeouts on SHC validation endpoints
      owner: Security Engineering
      addresses: CVE-2026-81876
      evidence: Source documents thread hanging via infinite loop
---

HAPI FHIR versions 6.9.11 and earlier are vulnerable to a denial-of-service (DoS) condition in the `SHCParser` component, identified as CVE-2026-81876. The vulnerability resides in the `inflate()` and `decompress()` methods of `SHCParser.java`, which process Smart Health Card (SHC) tokens. When the JWT header contains the `"zip":"DEF"` parameter, the parser attempts to decompress the payload. However, the implementation fails to validate the return state of the `Inflater` class, specifically ignoring `needsInput()` or zero-progress output. When provided with an empty or truncated raw DEFLATE stream, the parser enters an infinite loop, continuously consuming CPU cycles on the JVM worker thread. An attacker can exploit this by submitting crafted SHC content - either via file upload or URI input - to trigger validation, leading to thread exhaustion and potential service disruption in environments processing untrusted health records.

## Attack Chain

1. Attacker crafts a malicious SHC JWT where the header specifies `{"zip":"DEF"}`.
2. The payload is set to an empty or truncated byte sequence that fails standard DEFLATE expansion.
3. The malicious SHC is submitted to an application utilizing the HAPI FHIR library for health record processing.
4. The application triggers the validation workflow, passing the input to the `SHCParser` for processing.
5. The `SHCParser` reads the header, identifies the compression flag, and initiates the `inflate()` method.
6. The `Inflater.inflate()` method returns a zero-length result, causing the parser's `while` loop to execute indefinitely.
7. The JVM thread becomes pinned at 100% CPU usage for that core.
8. Concurrent requests overwhelm the thread pool, leading to complete service unavailability for legitimate users.

## Impact

Successful exploitation results in denial of service. Attackers can render applications incapable of processing legitimate health records by exhausting worker threads. The vulnerability affects critical infrastructure using HAPI FHIR, including FHIR validation servers, clinical portals, and health information exchange nodes. A minimal number of requests can effectively hang the service, impacting availability across sectors reliant on standard health record validation.

## Recommendation

Prioritize patching vulnerable HAPI FHIR components to mitigate CVE-2026-81876.
* Upgrade `org.hl7.fhir.r5`, `org.hl7.fhir.validation`, and `org.hl7.fhir.validation.cli` to a version beyond 6.9.11.
* Implement strict input validation on incoming SHC content before passing it to the HAPI FHIR library, specifically rejecting empty or non-compliant DEFLATE payloads.
* Monitor JVM thread activity for consistent high CPU utilization spikes originating from validation threads.
* Apply resource limits (timeouts) to file processing and validation threads to prevent single requests from pinning worker threads indefinitely.
