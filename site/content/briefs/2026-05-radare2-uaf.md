---
title: radare2 Use-After-Free Vulnerability in gdbr_threads_list() Function (CVE-2026-8695)
slug: 2026-05-radare2-uaf
description: radare2 version 6.1.5 contains a use-after-free vulnerability in the gdbr_threads_list() function, allowing remote attackers to trigger memory corruption by sending a valid qfThreadInfo response followed by a malformed qsThreadInfo response, potentially leading to denial of service or code execution through GDB remote debugging (CVE-2026-8695).
date: "2026-05-15T17:19:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - use-after-free
  - memory-corruption
  - gdb
  - debugging
vendors:
  - radare
products:
  - radare2 (6.1.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-8695
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8695
  - https://github.com/radareorg/radare2/commit/c213ad6894a1eb9086ac8bf5fae35757e9e1683c
  - https://github.com/radareorg/radare2/issues/25835
  - https://www.vulncheck.com/advisories/radare2-use-after-free-via-gdbr-threads-list
rules:
  - title: Detect Malformed GDB Thread Info Request
    description: Detects a malformed GDB qsThreadInfo request following a valid qfThreadInfo, potentially indicating CVE-2026-8695 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
rules_count: 1
---

radare2 is a reverse engineering and binary analysis framework. Version 6.1.5 contains a use-after-free vulnerability (CVE-2026-8695) within the `gdbr_threads_list()` function. This flaw can be exploited by remote attackers via GDB remote debugging. By sending a specifically crafted sequence of GDB thread information requests, specifically a valid `qfThreadInfo` followed by a malformed `qsThreadInfo` request, an attacker can trigger memory corruption. Successful exploitation could lead to a denial-of-service condition or potentially arbitrary code execution. This vulnerability poses a risk to systems where radare2 is used for debugging or analysis of potentially untrusted binaries.

## Attack Chain

1.  Attacker establishes a GDB remote debugging connection to the target radare2 instance.
2.  Attacker sends a valid `qfThreadInfo` request to initiate thread list retrieval.
3.  The radare2 instance processes the `qfThreadInfo` request and prepares the initial thread list.
4.  Attacker sends a malformed `qsThreadInfo` request as a continuation of thread list retrieval.
5.  The `gdbr_threads_list()` function attempts to process the malformed `qsThreadInfo` response.
6.  Due to the malformed data, the function accesses a previously freed memory location.
7.  This use-after-free condition triggers memory corruption.
8.  Depending on the memory layout and attacker-controlled data, this can lead to a denial of service (application crash) or potentially code execution.

## Impact

Successful exploitation of CVE-2026-8695 can result in a denial-of-service condition, where the radare2 application crashes, interrupting debugging or analysis tasks. In more sophisticated scenarios, attackers could potentially achieve arbitrary code execution by carefully manipulating the memory corruption caused by the use-after-free vulnerability. The impact is greatest in environments where radare2 is used to analyze potentially malicious binaries, as the attacker could leverage this vulnerability to compromise the analysis system.

## Recommendation

*   Upgrade to a version of radare2 that patches CVE-2026-8695.
*   Monitor network connections for unusual GDB debugging traffic using the `Detect Malformed GDB Thread Info Request` Sigma rule.
*   Consider restricting access to GDB debugging interfaces to trusted networks or users.
*   Review the provided references (especially the VulnCheck advisory) for more context on the exploitation details for CVE-2026-8695.
