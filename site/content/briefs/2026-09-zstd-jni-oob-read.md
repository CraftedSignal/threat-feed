---
title: Out-of-Bounds Memory Access in zstd-jni
slug: 2026-09-zstd-jni-oob-read
description: The zstd-jni library fails to validate sample buffer capacity in the Zstd.trainFromBufferDirect method, allowing attackers to trigger out-of-bounds memory access and JVM termination via crafted inputs.
date: "2026-09-09T16:58:46Z"
lastmod: "2026-09-09T16:58:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zstd-jni_project:zstd-jni:*:*:*:*:*:*:*:*
products:
  - zstd-jni (< 1.5.7-14)
cves:
  - id: CVE-2026-87824
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87824
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87825
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade zstd-jni to 1.5.7-14
      owner: IT Operations
      addresses: CVE-2026-87824
      evidence: NVD vulnerability entry
updates:
  - at: "2026-09-09T16:58:54Z"
    level: L2
    summary: added coverage for zstd-jni (< 1.5.7-14)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-87825
---

The zstd-jni library, a Java wrapper for the Zstandard compression algorithm, contains a critical vulnerability in the Zstd.trainFromBufferDirect method. Versions prior to 1.5.7-14 fail to properly validate the capacity of the samples buffer when processing compression dictionary training data. By providing crafted per-sample length arrays, an attacker can force the native Zstandard implementation to access memory addresses beyond the allocated buffer boundaries. This out-of-bounds memory read causes a segmentation fault within the native library, which subsequently results in the abrupt termination of the Java Virtual Machine (JVM). This vulnerability poses a significant denial-of-service risk to any Java application that utilizes zstd-jni to process untrusted compression dictionary training data.

## Impact

The vulnerability results in a high-severity denial-of-service condition due to the crash of the host JVM. Applications that accept user-provided training samples for Zstandard dictionary building are at risk of repeated service interruption or potential instability if the native memory corruption leads to unpredictable process states before the final crash occurs.

## Recommendation

- Upgrade the zstd-jni dependency to version 1.5.7-14 or later to remediate CVE-2026-87824.
- Audit all application entry points that pass user-supplied input to Zstd.trainFromBufferDirect to ensure that input length arrays are validated against expected bounds before processing.
- Monitor application logs for sudden JVM process exits accompanied by native crash dumps (hs_err_pid files) that indicate errors within the libzstd-jni native library.
