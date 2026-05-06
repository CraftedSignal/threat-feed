---
title: Axessh 4.2 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-axessh-buffer-overflow
description: Axessh 4.2 is vulnerable to a stack-based buffer overflow in the log file name field, allowing local attackers to execute arbitrary code by supplying an excessively long filename.
date: "2026-03-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - privilege-escalation
  - cve-2019-25607
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Local Account
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25607
  - http://www.labf.com
  - http://www.labf.com/download/axessh.exe
  - https://www.exploit-db.com/exploits/46858
  - https://www.exploit-db.com/exploits/46922
  - https://www.exploit-db.com/shellcodes/46281
  - https://www.vulncheck.com/advisories/axessh-local-stack-based-buffer-overflow-via-log-file-name
iocs:
  - type: url
    value: http://www.labf.com
  - type: url
    value: http://www.labf.com/download/axessh.exe
ioc_counts:
  url: 2
rules:
  - title: Detect Suspiciously Long Log Filenames
    description: Detects the creation of log files with excessively long names, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Axessh Process Spawning Suspicious Processes
    description: Detects Axessh spawning processes that are not normally associated with its function, possibly indicating code execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Axessh 4.2, a software of unknown purpose from labf.com, is susceptible to a stack-based buffer overflow vulnerability (CVE-2019-25607). This vulnerability was reported on March 22, 2026. A local attacker can exploit this flaw by providing an overly long filename for the log file, overflowing a buffer of 214 bytes. Successful exploitation allows the attacker to overwrite the instruction pointer and execute arbitrary code with system privileges. This poses a significant risk to systems running Axessh 4.2, as it allows for local privilege escalation and potential system compromise. The vulnerability is present due to insufficient bounds checking on the length of the provided log filename.

## Attack Chain

1.  The attacker gains local access to a system running Axessh 4.2.
2.  The attacker identifies the logging functionality within Axessh 4.2.
3.  The attacker crafts an excessively long filename, exceeding 214 bytes.
4.  The attacker provides the malicious filename as input for the log file name.
5.  Axessh 4.2 attempts to write the log file with the attacker-controlled name.
6.  The excessively long filename overflows the buffer on the stack.
7.  The buffer overflow overwrites the instruction pointer.
8.  The attacker gains arbitrary code execution with the privileges of the Axessh process.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code with system privileges. This could lead to complete system compromise, including data theft, installation of malware, or denial of service. The CVSS v3.1 score of 8.4 indicates a high severity. Due to the nature of local privilege escalation, the impact is limited to systems where an attacker already has a foothold.

## Recommendation

*   Apply any available patches or updates for Axessh 4.2 provided by the vendor (check http://www.labf.com).
*   Monitor process creation events for suspicious processes spawned by Axessh (use the process_creation category).
*   Deploy the Sigma rule to detect potential exploitation attempts by monitoring for processes that create log files with unusually long names.
*   Block access to the identified URLs associated with the exploit (http://www.labf.com, https://www.exploit-db.com/exploits/46858) at the network perimeter.
