---
title: Heap Buffer Overflow in Oj.dump Exception Serialization via Large Indent (CVE-2026-54896)
slug: 2026-06-oj-heap-buffer-overflow
description: The `Oj.dump` function in the Ruby `oj` gem, when operating in object mode, is vulnerable to a heap buffer overflow (CVE-2026-54896) when serializing `Exception` objects with an excessively large `:indent` value, leading to memory corruption and potential denial of service or remote code execution.
date: "2026-06-19T19:57:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ruby
  - vulnerability
  - heap-overflow
vendors:
  - Oj
products:
  - oj gem
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-35w3-pjm6-wj95
rules:
  - title: Detects CVE-2026-54896 Exploitation - Ruby Process Crash (Windows)
    description: Detects ruby.exe process termination associated with Windows Error Reporting (WerFault.exe) or unusual exit codes, which may indicate a crash resulting from CVE-2026-54896 exploitation.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2026-54896 Exploitation - Ruby Core Dump Creation (Linux)
    description: Detects the creation of core dump files by a ruby process, which can indicate a critical crash, potentially due to exploitation of CVE-2026-54896 (heap buffer overflow).
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The `oj` Ruby gem, specifically its `Oj.dump` function in object serialization mode, is affected by a heap buffer overflow vulnerability, identified as CVE-2026-54896. This flaw impacts all versions of the gem that include the `ext/oj/dump.h` component, up to and including version 3.17.1. The vulnerability occurs when an application attempts to serialize an `Exception` object using `Oj.dump` with a particularly large `:indent` value (e.g., 5000). The underlying C implementation pre-allocates a buffer based on the object's attributes but fails to account for the substantial additional memory required by the indent string, leading to repeated writes beyond the buffer's boundary. This memory corruption can result in application crashes, denial of service, or potentially enable arbitrary code execution. Defenders should prioritize patching and validating `oj` gem versions in their Ruby applications.

## Attack Chain

1.  **Initial Input**: An attacker sends crafted JSON input to a vulnerable application that utilizes the `oj` gem.
2.  **Object Deserialization**: The application processes the attacker's input using `Oj.load` in object mode, which creates a Ruby `Exception` object (e.g., `RuntimeError`) from the JSON.
3.  **Vulnerable Serialization Call**: A legitimate application component subsequently attempts to serialize this `Exception` object back to JSON using `Oj.dump`, with an excessively large `:indent` value (e.g., 5000), which might be attacker-controlled or a misconfigured application setting.
4.  **Insufficient Buffer Allocation**: Internally, `Oj.dump` (specifically `dump_obj_attrs`) allocates a memory buffer for the serialization output, but this buffer's size is based on the object's attributes and does not adequately account for the combined size of the large indentation strings.
5.  **Heap Buffer Overflow**: The `fill_indent` function is repeatedly called during serialization to add indentation. When writing the large indent string (e.g., 5000 bytes) into the pre-allocated buffer, it exceeds the available space.
6.  **Memory Corruption and Impact**: This repeated out-of-bounds writing causes a heap buffer overflow, corrupting adjacent memory. This typically leads to a denial of service through an application crash or, in more advanced scenarios, could be leveraged for arbitrary code execution.

## Impact

The primary impact of CVE-2026-54896 is memory corruption, leading to the affected Ruby application crashing and resulting in a denial of service. If an attacker can reliably control the execution flow after the overflow, it could potentially be escalated to remote code execution. Although no specific victim counts or targeted sectors have been disclosed, any Ruby application utilizing the `oj` gem in a manner that deserializes untrusted input and subsequently reserializes `Exception` objects with large indent values is at risk.

## Recommendation

*   **Patch CVE-2026-54896**: Immediately upgrade the `oj` gem to version `3.17.2` or later to mitigate CVE-2026-54896.
*   **Implement Application-Level Controls**: Developers should ensure that user-controlled input does not dictate the `:indent` parameter for `Oj.dump` calls and avoid using excessively large hardcoded indent values.
*   **Deploy Sigma Rules**: Deploy the provided Sigma rules to your SIEM solution to detect abnormal `ruby` process terminations or crash dump creations, which may indicate exploitation attempts.
*   **Enable Process Monitoring**: Ensure robust process creation and termination logging is enabled for Ruby applications (e.g., Sysmon on Windows, Auditd on Linux) to capture potential crash-related events.
