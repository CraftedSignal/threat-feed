---
title: Unbounded StringBuilder Growth in jackson-core via DataInput
slug: 2026-10-jackson-core-dos
description: The jackson-core library suffers from a denial-of-service vulnerability (CVE-2026-89425) where malformed tokens in DataInput-backed parsers cause unbounded memory consumption, leading to potential JVM process crashes.
date: "2026-10-01T20:22:17Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:fasterxml:jackson-core:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - java
vendors:
  - FasterXML
products:
  - jackson-core (2.8.0 - 2.18.10)
  - jackson-core (2.19.0 - 2.21.6)
  - jackson-core (2.22.0 - 2.22.2)
  - jackson-core (3.0.0 - 3.1.6)
  - jackson-core (3.2.0 - 3.2.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This allows an attacker to send a specially crafted, long malformed input that causes the application to perform unbounded StringBuilder growth, leading to an OutOfMemoryError and crashing the JVM process.
    confidence_band: high
cves:
  - id: CVE-2026-89425
    cvss: 7.5
    epss: 0.00492
references:
  - https://github.com/advisories/GHSA-7hhh-6rmp-j9qf
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89425
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Audit codebase for usage of JsonFactory.createParser(DataInput)
      owner: Application Security
      due: 72h
      evidence: Source code assessment
  mitigation_plan:
    - priority: immediate
      action: Replace DataInput-based parsing with InputStream-based parsing for untrusted data
      owner: Development
      addresses: CVE-2026-89425
      evidence: Technical analysis demonstrating InputStream bounds enforcement
---

FasterXML jackson-core is affected by an unbounded StringBuilder growth vulnerability located in the `UTF8DataInputJsonParser._reportInvalidToken()` method. This defect occurs when the parser is initialized via `JsonFactory.createParser(DataInput)`. Unlike other parser implementations in the library that correctly enforce a maximum error token length, this specific implementation fails to check `ErrorReportConfiguration.getMaxErrorTokenLength()` (default 256) when building exception messages for invalid tokens.

An attacker can trigger this by providing a long, malformed JSON token. Because the implementation appends characters one-by-one to an unbounded StringBuilder without bounds checking, the internal structure grows linearly with the input payload size. This expansion, compounded by byte-to-char conversion, can rapidly deplete heap memory. Critically, existing configuration mitigations such as `maxDocumentLength` or `maxStringLength` do not apply to this code path, leaving applications using the `DataInput` parser implementation without built-in defense against this denial-of-service vector.

## Impact

Successful exploitation leads to an `OutOfMemoryError` within the JVM hosting the vulnerable application. By supplying a large, malformed token, an attacker can cause the process to allocate excessive memory, forcing a crash and resulting in a denial-of-service for any system relying on this parser to process external JSON input. This affects a wide range of Jackson versions (2.8.0 through 3.2.2).

## Recommendation

1. Upgrade `jackson-core` to a patched version once provided by the vendor.
2. If immediate patching is not possible, audit applications to determine if `JsonFactory.createParser(DataInput)` is used to process untrusted input.
3. Where possible, migrate from `DataInput` sources to `InputStream` or `Reader` based parsers, which currently enforce `maxErrorTokenLength` bounds correctly.
4. Implement application-level request size limits before passing data to the Jackson parser to mitigate the potential impact of large malicious payloads.
