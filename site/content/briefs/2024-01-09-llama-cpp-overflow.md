---
title: llama.cpp Integer Overflow Vulnerability Leading to Potential RCE
slug: 2024-01-09-llama-cpp-overflow
description: A heap-based buffer overflow vulnerability exists in llama.cpp due to an integer overflow in the `ggml_nbytes` function, allowing attackers to potentially achieve Remote Code Execution (RCE) by crafting malicious GGUF files.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - llama.cpp
  - integer_overflow
  - rce
  - heap_overflow
vendors:
  - llama.cpp
products:
  - llama.cpp
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33298
rules:
  - title: Detect Suspicious llama.cpp Child Processes
    description: Detects unexpected child processes spawned by llama.cpp, potentially indicating code execution after a buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious GGUF File Loading
    description: Detects attempts to load GGUF files with unusually large or suspicious tensor dimensions that could trigger the integer overflow vulnerability in `ggml_nbytes`.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

llama.cpp is a C/C++ library used for inference of various Large Language Models (LLMs). A critical vulnerability, identified as CVE-2026-33298, exists in versions prior to commit b7824. This vulnerability stems from an integer overflow within the `ggml_nbytes` function. Attackers can exploit this by crafting a malicious GGUF file containing specifically designed tensor dimensions. This crafted file causes `ggml_nbytes` to incorrectly calculate the required memory size, returning a value significantly smaller than needed. Consequently, when the application processes the tensor, a heap-based buffer overflow occurs, potentially leading to memory corruption and Remote Code Execution (RCE). Organizations utilizing affected versions of llama.cpp are at risk of exploitation if processing untrusted GGUF files.

## Attack Chain

1.  An attacker crafts a malicious GGUF file designed with specific tensor dimensions to trigger the integer overflow.
2.  The victim application, using a vulnerable version of llama.cpp (prior to commit b7824), attempts to load the malicious GGUF file using standard file processing functions.
3.  During the loading process, the `ggml_nbytes` function is called to calculate the memory required for the tensor defined within the GGUF file.
4.  Due to the crafted tensor dimensions, `ggml_nbytes` experiences an integer overflow, returning a much smaller memory size than actually required. For example, it may return 4MB when Exabytes are needed.
5.  The application allocates a buffer based on the undersized value returned by `ggml_nbytes`.
6.  The application proceeds to copy tensor data from the GGUF file into the undersized buffer, causing a heap-based buffer overflow.
7.  The buffer overflow corrupts adjacent memory regions on the heap, potentially overwriting critical data structures or executable code.
8.  If the overwritten memory contains executable code, the attacker can achieve Remote Code Execution (RCE) by hijacking the program's control flow to execute arbitrary code.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the affected system. Given the nature of LLM applications, this could lead to data exfiltration, system compromise, or further lateral movement within the network. The CVSS v3.1 base score is 7.8, highlighting the high potential for impact. If a llama.cpp application processes untrusted GGUF files, it is vulnerable to remote code execution.

## Recommendation

*   Upgrade llama.cpp to commit b7824 or later to patch the integer overflow vulnerability in `ggml_nbytes`.
*   Implement input validation and sanitization for GGUF files to prevent the processing of malicious files with crafted tensor dimensions.
*   Enable process creation logging to monitor for unexpected processes spawned by llama.cpp, which could indicate successful exploitation (see Sigma rule "Detect Suspicious llama.cpp Child Processes").
*   Implement the Sigma rule "Detect Malicious GGUF File Loading" to detect attempts to load GGUF files with characteristics that may indicate exploitation attempts.
