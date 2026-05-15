---
title: Radare2 Use-After-Free Vulnerability in GDB Client (CVE-2026-8696)
slug: 2026-05-radare2-uaf
description: Radare2 version 6.1.5 contains a use-after-free vulnerability (CVE-2026-8696) in the gdbr_pids_list() function, allowing remote attackers to cause a denial of service or potentially execute arbitrary code via malformed thread information responses.
date: "2026-05-15T21:18:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - use-after-free
  - denial-of-service
  - radare2
products:
  - radare2 6.1.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-8696
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8696
rules:
  - title: Detects CVE-2026-8696 Exploitation — Radare2 GDB Malformed Thread Info Response
    description: Detects CVE-2026-8696 exploitation — monitors network connections for GDB traffic and flags connections with excessively large data transfers immediately following thread info requests, which may indicate an attempt to trigger the use-after-free vulnerability.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - windows
  - title: Detects CVE-2026-8696 Exploitation — Radare2 Suspicious Process Creation
    description: Detects CVE-2026-8696 exploitation — identifies unusual child processes spawned by Radare2, potentially indicating successful code execution via the use-after-free.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Radare2 is susceptible to a use-after-free vulnerability, CVE-2026-8696, present in version 6.1.5. The flaw resides within the `gdbr_pids_list()` function of the GDB client core. Remote attackers can exploit this vulnerability by transmitting crafted thread information responses. Successful exploitation can lead to a denial-of-service condition or, potentially, the execution of arbitrary code on the affected system. The root cause is identified as double-free memory corruption, which occurs during the cleanup process when `qsThreadInfo` fails after `qfThreadInfo` successfully allocates `RDebugPid` structures. This poses a significant risk to systems utilizing Radare2 for debugging or reverse engineering purposes, as a malicious actor could disrupt operations or gain unauthorized control.

## Attack Chain

1.  Attacker establishes a connection to the Radare2 GDB server.
2.  Attacker sends a `qfThreadInfo` command to request thread information.
3.  The `qfThreadInfo` function in Radare2 allocates memory for `RDebugPid` structures.
4.  Attacker sends a crafted response designed to cause `qsThreadInfo` to fail.
5.  `qsThreadInfo` fails to process the malformed thread information response.
6.  The error handling path attempts to clean up the allocated `RDebugPid` structures.
7.  Due to a flaw in the cleanup logic, the same memory is freed twice, triggering a double-free condition.
8.  The use-after-free vulnerability is triggered, leading to a denial-of-service or potential arbitrary code execution.

## Impact

Successful exploitation of this vulnerability (CVE-2026-8696) can result in a denial-of-service condition, rendering the Radare2 instance unusable. In a more severe scenario, attackers might be able to leverage the memory corruption to execute arbitrary code on the affected system, potentially gaining complete control. The impact is primarily on systems using Radare2 for debugging, reverse engineering, and analysis. This could impact software development, security research, and incident response activities.

## Recommendation

*   Upgrade to a patched version of Radare2 that addresses CVE-2026-8696 as soon as a patch is available.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts targeting CVE-2026-8696.
*   Monitor network traffic for malformed GDB thread information responses using the `network_connection` Sigma rule to identify potential exploitation attempts.
*   Enable process creation logging on systems running Radare2 to facilitate detection of malicious activities using the `process_creation` Sigma rule.
