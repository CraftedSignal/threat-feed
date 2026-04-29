---
title: AIDA64 Extreme 5.99.4900 Structured Exception Handler Buffer Overflow
slug: 2026-03-aida64-buffer-overflow
description: AIDA64 Extreme 5.99.4900 is vulnerable to a structured exception handler buffer overflow, allowing local attackers to execute arbitrary code by supplying a malicious CSV log file path through the Hardware Monitoring logging preferences.
date: "2026-03-24T12:16:02Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - aida64
  - buffer-overflow
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25629
  - https://www.vulncheck.com/advisories/aida64-extreme-seh-buffer-overflow-via-logging
  - https://www.exploit-db.com/exploits/46660
iocs:
  - type: url
    value: http://download.aida64.com/aida64extreme599.exe
  - type: url
    value: https://www.aida64.com
  - type: url
    value: https://www.exploit-db.com/exploits/46660
  - type: url
    value: https://www.vulncheck.com/advisories/aida64-extreme-seh-buffer-overflow-via-logging
ioc_counts:
  url: 4
rules:
  - title: Detect AIDA64 Suspicious Log File Access
    description: Detects AIDA64 accessing potentially malicious CSV log files, indicating a possible buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
  - title: Detect AIDA64 Command Line Process Creation
    description: Detects AIDA64 spawning command-line processes, which is unexpected behavior and could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

AIDA64 Extreme version 5.99.4900 is susceptible to a structured exception handler (SEH) buffer overflow vulnerability. This flaw enables a local attacker to execute arbitrary code on a targeted system. The attack vector involves crafting a malicious CSV log file path and configuring AIDA64's Hardware Monitoring logging preferences to utilize it. When the AIDA64 application attempts to process this specially crafted log file, it triggers a buffer overflow in the SEH, enabling the attacker to inject and execute arbitrary shellcode. This vulnerability poses a significant risk to systems running the affected AIDA64 version, potentially leading to complete system compromise by local users.

## Attack Chain

1. The attacker gains local access to a system running AIDA64 Extreme 5.99.4900.
2. The attacker crafts a malicious CSV log file containing shellcode designed to exploit the SEH buffer overflow.
3. The attacker opens AIDA64 Extreme and navigates to the Hardware Monitoring logging preferences.
4. Within the logging preferences, the attacker specifies the path to the malicious CSV log file.
5. AIDA64 attempts to process the specified log file, triggering the buffer overflow.
6. The injected shellcode overwrites the structured exception handler.
7. When an exception occurs during log processing, the overwritten SEH redirects execution to the attacker's shellcode.
8. The attacker's shellcode executes arbitrary commands, potentially granting them full control of the system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code with the privileges of the AIDA64 process. This could lead to complete system compromise, data theft, or installation of malware. While the exploit requires local access, the severity is high due to the potential for privilege escalation and the ease with which a malicious log file path can be configured within the application.

## Recommendation

*   Monitor process execution for AIDA64 (aida64.exe) attempting to access unusual or suspicious file paths, especially CSV files, using the `Detect AIDA64 Suspicious Log File Access` Sigma rule.
*   Enable file access monitoring to capture the file paths being accessed by AIDA64.
*   Apply appropriate access controls to prevent unauthorized local users from modifying AIDA64's logging preferences.
