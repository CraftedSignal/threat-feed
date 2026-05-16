---
title: CVE-2026-44673 libyang Integer Overflow Leads to Heap Buffer Overflow
slug: 2026-05-libyang-heap-overflow
description: CVE-2026-44673 describes an integer overflow in the lyb_read_string() function of the libyang library that can lead to a heap buffer overflow, potentially allowing for arbitrary code execution.
date: "2026-05-16T07:16:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - libyang
  - heap-buffer-overflow
  - integer-overflow
  - CVE-2026-44673
vendors:
  - Microsoft
cves:
  - id: CVE-2026-44673
    cvss: 7.5
    epss: 0.00052
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44673
rules:
  - title: Detect CVE-2026-44673 Exploitation - Suspicious Process Execution
    description: Detects CVE-2026-44673 exploitation — Monitors for suspicious processes spawned after a vulnerable application processes a malicious LYB file, potentially indicating code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-44673 Exploitation - Unsigned Binary Execution
    description: Detects CVE-2026-44673 exploitation — Monitors for unsigned binaries being executed after the parsing of LYB files by the vulnerable application, indicating unauthorized code execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - image_load
      - windows
rules_count: 2
---

CVE-2026-44673 describes a vulnerability within the libyang library, specifically an integer overflow in the `lyb_read_string()` function. The vulnerability occurs when handling string lengths during the parsing of LYB (yang binary) formatted data. An attacker could potentially exploit this flaw by crafting a malicious LYB file that triggers an integer overflow, leading to a heap buffer overflow during memory allocation and data processing. Successful exploitation could allow an attacker to execute arbitrary code within the context of the application using the vulnerable library. The vulnerability was published in May 2026.

## Attack Chain

1.  An attacker crafts a malicious LYB file containing a specially formatted string length field.
2.  The application using the vulnerable libyang library attempts to parse the LYB file.
3.  The `lyb_read_string()` function is called to read the string from the LYB file.
4.  The function attempts to allocate memory on the heap based on the provided length.
5.  Due to the crafted input, an integer overflow occurs during the length calculation.
6.  This results in a smaller-than-expected memory allocation.
7.  The `lyb_read_string()` function proceeds to write the string data into the undersized buffer, causing a heap buffer overflow.
8.  The attacker leverages the heap buffer overflow to overwrite adjacent memory regions, potentially leading to arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-44673 can lead to arbitrary code execution within the context of the application utilizing the vulnerable libyang library. This could allow an attacker to gain control of the affected system, potentially leading to data theft, system compromise, or denial of service. The specific impact will depend on the privileges of the application and the attacker's ability to craft a successful exploit.

## Recommendation

*   Apply the security patch provided by Microsoft to address CVE-2026-44673 as soon as it becomes available.
*   Deploy the Sigma rule below to detect potential exploitation attempts based on process execution patterns after the vulnerability is triggered.
*   Monitor network traffic for suspicious LYB file uploads or transfers as a potential initial access vector.
