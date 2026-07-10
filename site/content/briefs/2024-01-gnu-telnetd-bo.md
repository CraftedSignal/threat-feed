---
title: GNU telnetd Buffer Overflow Vulnerability (CVE-2026-32746)
slug: 2024-01-gnu-telnetd-bo
description: A critical buffer overflow vulnerability exists in GNU telnetd (CVE-2026-32746), potentially allowing remote code execution on affected Linux systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-32746
  - telnetd
  - buffer-overflow
  - linux
vendors:
  - GNU
products:
  - telnetd
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.reddit.com/r/netsec/comments/1rxl75t/cve202632746_gnu_telnetd_buffer_overflow_poc/
  - https://pwn.guide/free/other/cve-2026-32746
rules:
  - title: Detect Telnetd Process Creation
    description: Detects the creation of the telnetd process on Linux systems, which is often an indicator of a server running
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1021.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Large Input to Telnetd
    description: Detects unusually large input strings to telnetd, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Telnetd Shell Spawn
    description: Detects shell processes spawned by telnetd, which is abnormal behavior.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A critical buffer overflow vulnerability, tracked as CVE-2026-32746, has been identified in GNU telnetd. This vulnerability, if exploited, could allow an unauthenticated attacker to execute arbitrary code on a vulnerable system. A proof-of-concept (PoC) exploit is publicly available, increasing the risk of exploitation. The vulnerability affects Linux systems running vulnerable versions of GNU telnetd. Defenders should prioritize patching and implementing detection measures to mitigate potential exploitation. This vulnerability poses a significant threat to system integrity and confidentiality.

## Attack Chain

1.  An attacker identifies a vulnerable system running GNU telnetd.
2.  The attacker connects to the telnet service on the target system (typically port 23).
3.  The attacker sends a specially crafted input string to the telnetd service, exploiting the buffer overflow in the telnetd process.
4.  The overflow overwrites critical memory regions, including the return address on the stack.
5.  The attacker redirects execution flow to attacker-controlled code injected into the process's memory space via the overflow.
6.  The attacker's code executes with the privileges of the telnetd process (typically root or a system account).
7.  The attacker gains a remote shell on the target system.
8.  The attacker can then perform privileged actions, install malware, or exfiltrate data.

## Impact

Successful exploitation of CVE-2026-32746 can lead to complete system compromise. An attacker could gain root access, allowing them to install malware, steal sensitive data, or disrupt services. The vulnerability affects any Linux system running a vulnerable version of GNU telnetd. Given the ease of exploitation (due to the availability of a PoC), unpatched systems are at high risk of being compromised.

## Recommendation

*   Apply the patch for CVE-2026-32746 to all affected systems immediately.
*   Disable telnet service if it is not required. Consider using SSH instead.
*   Deploy the Sigma rules provided in this brief to detect potential exploitation attempts.
*   Enable process creation logging on Linux systems to enable the provided Sigma rules.
