---
title: Memory Management Vulnerability in llama.cpp Android JNI Wrapper
slug: 2026-08-llama-jni-memory-corruption
description: A memory management mismatch in the llama.cpp Android JNI wrapper leads to heap metadata corruption, enabling potential denial of service or arbitrary code execution.
date: "2026-08-06T17:25:52Z"
lastmod: "2026-08-06T23:30:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - integer-overflow
  - llama-cpp
vendors:
  - ggml-org
products:
  - llama.cpp (b1886 through b7445)
  - llama.cpp (b1283 - b9058)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can trigger this memory management mismatch to cause denial of service through process crashes or potentially achieve arbitrary code execution depending on allocator state.
    confidence_band: high
cves:
  - id: CVE-2026-43622
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43622
  - https://github.com/ggml-org/llama.cpp/releases/tag/b7446
  - https://github.com/ggml-org/llama.cpp/commit/5c0d18881e0e9794c96b2602736b758bac9d9388
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43627
  - https://github.com/Vladimir-tokarev-cyera/llama-cpp-security-patches
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Inventory Android applications utilizing llama.cpp to identify builds between b1886 and b7445.
      owner: Development
      due: 48h
      evidence: llama.cpp builds b1886 through b7445 contain a double free vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable llama.cpp dependencies to build b7446.
      owner: Development
      addresses: CVE-2026-43622
      evidence: Issue was addressed in build b7446.
updates:
  - at: "2026-08-06T23:30:08Z"
    level: L2
    summary: added coverage for llama.cpp (b1283 - b9058)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-43627
---

A security vulnerability exists in llama.cpp builds b1886 through b7445, specifically within the LLaMA-Android JNI (Java Native Interface) wrapper. The vulnerability is caused by a memory management mismatch where the `new_1batch()` function allocates memory using the standard `malloc()` C function, but the corresponding `free_1batch()` function attempts to deallocate that memory using the C++ `delete` operator. 

This mismatch between memory allocation and deallocation routines results in heap metadata corruption. An attacker capable of triggering this code path - typically through an application utilizing the affected library on Android - can induce a denial-of-service (DoS) condition via process crashes. Depending on the state of the heap allocator at the time of the corruption, there is potential for an attacker to achieve arbitrary code execution. This issue was addressed in build b7446.

## Impact

Successful exploitation can lead to a denial of service on Android applications integrating the affected llama.cpp builds. In scenarios where heap manipulation is possible, an attacker could potentially gain unauthorized code execution within the context of the vulnerable application, impacting the confidentiality, integrity, and availability of data processed by the affected mobile application.

## Recommendation

- Upgrade to llama.cpp build b7446 or later across all Android application deployments.
- Audit Android applications that bundle llama.cpp libraries for versions falling within the b1886-b7445 range.
- Implement memory sanitizers (such as HWAddressSanitizer for Android) during the development and testing lifecycle to detect heap corruption bugs and mismatched memory management routines.
- Review custom JNI wrappers for consistent use of allocation and deallocation primitives.
