---
title: Unbounded DEFLATE Decompression Vulnerability in HAPI FHIR
slug: 2026-09-hapi-fhir-dos
description: The HAPI FHIR SHCParser component contains an unbounded DEFLATE decompression flaw (CVE-2026-81875) allowing attackers to trigger memory exhaustion and denial-of-service.
date: "2026-09-18T01:11:51Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:hl7:hapi_fhir:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - cve-2026-81875
vendors:
  - HL7
products:
  - HAPI FHIR (<= 6.9.11)
  - HAPI FHIR validation.cli (<= 5.0.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker who can submit SHC content for validation can craft a small compressed JWT payload that expands to a very large byte array, causing memory exhaustion or severe garbage collection pressure.
    confidence_band: high
cves:
  - id: CVE-2026-81875
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-3w98-rrpr-fprr
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade HAPI FHIR libraries to versions exceeding 6.9.11
      owner: IT Operations
      due: 72h
      evidence: Source advisory notes vulnerability in versions <= 6.9.11
  mitigation_plan:
    - priority: immediate
      action: Implement strict payload size limits at the API gateway
      owner: Application Security
      addresses: CVE-2026-81875
      evidence: The parser lacks internal size limits, requiring external mitigation
---

The HAPI FHIR library contains a vulnerability (CVE-2026-81875) in its `SHCParser` component, specifically within the `inflate()` and `decompress()` methods found in `SHCParser.java`. The library improperly handles the decompression of Smart Health Card (SHC) JWT payloads when the header specifies `"zip":"DEF"`. Because the `inflate()` function uses a `ByteArrayOutputStream` without enforcing a maximum output size, a small, highly compressed malicious payload can be expanded into an arbitrarily large byte array in memory. An attacker who can supply SHC content for validation can exploit this to force extreme heap allocation. This vulnerability leads to severe garbage collection pressure, performance degradation, and potential application crashes due to `OutOfMemoryError`. The flaw affects `org.hl7.fhir.r5` and `org.hl7.fhir.validation` versions up to and including 6.9.11, as well as `org.hl7.fhir.validation.cli` up to version 5.0.0.

## Impact

The primary impact is a denial-of-service (DoS) condition affecting any validator or application utilizing the vulnerable HAPI FHIR components. Successful exploitation results in significant heap memory exhaustion, high CPU utilization during the decompression process, and potential application unavailability. This poses a high risk to healthcare-related infrastructure that processes Smart Health Cards, as an attacker can repeatedly submit crafted payloads to cause sustained service disruption or process termination.

## Recommendation

1. Upgrade HAPI FHIR components to versions beyond 6.9.11 to incorporate the necessary decompression size limits.
2. For applications using `org.hl7.fhir.validation.cli`, ensure an upgrade path to a version beyond 5.0.0 is utilized.
3. Implement strict input validation or size constraints at the perimeter or API gateway level for any service that accepts and validates SHC/JWT payloads to reject oversized input before it reaches the `SHCParser`.
4. Monitor application heap usage and garbage collection metrics for anomalous spikes coinciding with the processing of incoming FHIR validation requests.
