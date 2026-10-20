---
title: CVE-2026-109395 - Out-of-Bounds Memory Access in Ning compress-lzf
slug: 2026-10-compress-lzf-oob
description: Ning compress-lzf versions prior to 1.2.0 are vulnerable to an out-of-bounds memory access flaw in the UnsafeChunkDecoder, which can be exploited via crafted LZF streams to leak JVM heap memory or cause application crashes.
date: "2026-10-20T02:31:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:ning:compress-lzf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-safety
  - java
vendors:
  - Ning
products:
  - compress-lzf (< 1.2.0)
cves:
  - id: CVE-2026-109395
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109395
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Ning compress-lzf to version 1.2.0 or later
      owner: IT Operations
      due: 72h
      evidence: Source notes version 1.2.0 as the remediation for CVE-2026-109395
  mitigation_plan:
    - priority: immediate
      action: Upgrade compress-lzf to 1.2.0
      owner: IT Operations
      addresses: CVE-2026-109395
      evidence: Vulnerability is addressed in version 1.2.0
---

Ning compress-lzf versions before 1.2.0 contain an out-of-bounds (OOB) memory access vulnerability located within the `UnsafeChunkDecoder` component. This component utilizes `sun.misc.Unsafe` for high-performance decompression; however, it fails to properly validate back-references and literal runs during the decompression process. An attacker can provide a specifically crafted LZF compressed stream to any application utilizing the default `LZFDecoder`. When the application attempts to process this malicious stream, the vulnerability is triggered, leading to either an application-wide crash (Denial of Service) or the exposure and leakage of unrelated JVM heap memory into the output buffer. This vulnerability is significant for any Java-based environment processing untrusted compressed data, as it allows for the potential exfiltration of sensitive information stored in the heap.

## Attack Chain

1. Attacker identifies an application that utilizes the Ning compress-lzf library (versions < 1.2.0) to process input data.
2. Attacker crafts a malicious LZF stream designed to trigger the validation flaw in the `UnsafeChunkDecoder`.
3. Attacker submits the crafted LZF stream through an application entry point (e.g., API request, file upload, or network packet).
4. The target application passes the attacker-supplied payload to the `LZFDecoder` for decompression.
5. The `UnsafeChunkDecoder` reads memory beyond the bounds of the expected input buffer due to improper back-reference checks.
6. The system places the OOB memory data into the application's output buffer or crashes the JVM process.
7. Attacker retrieves the processed output, which now contains unauthorized heap memory contents, or observes the application service termination.

## Impact

Successful exploitation of CVE-2026-109395 can result in the unauthorized disclosure of sensitive data residing in the JVM heap, such as session tokens, cryptographic keys, or user credentials. Furthermore, the vulnerability allows for reliable application crashes, enabling a denial-of-service attack against the affected service. Given the prevalence of Java-based web applications, this vulnerability poses a high risk to availability and confidentiality.

## Recommendation

* Upgrade the Ning compress-lzf library to version 1.2.0 or later immediately to incorporate the necessary memory bounds validation.
* Audit applications that accept compressed LZF input to identify those utilizing the vulnerable `UnsafeChunkDecoder`.
* If upgrading is not immediately feasible, implement strict input validation and sanitization for all data passed to decompression routines.
