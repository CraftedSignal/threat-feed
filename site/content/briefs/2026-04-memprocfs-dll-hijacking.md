---
title: MemProcFS DLL and Shared Library Hijacking Vulnerability
slug: 2026-04-memprocfs-dll-hijacking
description: MemProcFS before 5.17 is susceptible to DLL and shared-library hijacking due to unsafe library-loading patterns, allowing attackers to achieve arbitrary code execution by placing malicious libraries or manipulating the library search path.
date: "2026-04-08T22:16:23Z"
severities:
  - high
tags:
  - dll-hijacking
  - library-hijacking
  - code-execution
  - memprocfs
  - cve-2026-40031
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
cves:
  - id: CVE-2026-40031
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40031
  - https://github.com/ufrisk/MemProcFS/commit/df80e6e83641f5004025ce661e6dd8139028d7b5
  - https://github.com/ufrisk/MemProcFS/releases/tag/v5.17
  - https://mobasi.ai/sentinel
  - https://www.vulncheck.com/advisories/memprocfs-dll-shared-library-hijacking
rules:
  - title: Detect MemProcFS Loading DLL from Current Directory
    description: Detects MemProcFS loading a DLL from the current working directory, which could indicate a DLL hijacking attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious LD_LIBRARY_PATH Manipulation
    description: Detects suspicious attempts to manipulate the LD_LIBRARY_PATH environment variable, potentially for shared library hijacking on Linux.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1574.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

MemProcFS before version 5.17 is vulnerable to DLL and shared library hijacking due to unsafe library loading practices. Specifically, the application uses bare-name `LoadLibraryU` and `dlopen` calls without proper path qualification for `vmmpyc`, `libMSCompression`, and plugin DLLs. This vulnerability, identified as CVE-2026-40031, exists across six attack surfaces. The vulnerability was reported by VulnCheck. Exploitation can occur on both Windows and Linux systems where MemProcFS is…
