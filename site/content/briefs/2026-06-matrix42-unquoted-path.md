---
title: 'CVE-2016-20095: Matrix42 Remote Control Host Unquoted Service Path Privilege Escalation'
slug: 2026-06-matrix42-unquoted-path
description: A local attacker can exploit CVE-2016-20095, an unquoted service path vulnerability in Matrix42 Remote Control Host version 3.20.0031, to achieve arbitrary code execution with SYSTEM privileges by placing a malicious executable named 'Program.exe' in the 'C:\Program Files\' directory, leading to privilege escalation when the vulnerable service starts.
date: "2026-06-19T15:56:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - unquoted-service-path
  - windows
  - matrix42
vendors:
  - Matrix42
products:
  - Matrix42 Remote Control Host 3.20.0031
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
cves:
  - id: CVE-2016-20095
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20095
  - https://www.exploit-db.com/exploits/39908
  - https://www.matrix42.com/
  - https://www.vulncheck.com/advisories/matrix42-remote-control-host-unquoted-path-privilege-escalation
rules:
  - title: Detects CVE-2016-20095 Exploitation - Program.exe Execution from Program Files
    description: Detects the execution of 'Program.exe' directly from 'C:\Program Files\' with SYSTEM privileges, indicative of an unquoted service path exploitation (CVE-2016-20095).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.008
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2016-20095 Pre-Exploitation - Program.exe File Creation
    description: Detects the creation of an executable named 'Program.exe' directly within 'C:\Program Files\', a common step in exploiting unquoted service path vulnerabilities like CVE-2016-20095.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.008
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2016-20095 describes an unquoted service path vulnerability impacting Matrix42 Remote Control Host version 3.20.0031. Specifically, the `FastViewerRemoteService` and `FastViewerRemoteProxy` services are susceptible. This flaw allows a local attacker, who already has basic user access to a vulnerable system, to escalate their privileges to SYSTEM. The vulnerability arises because the service executable's path is not enclosed in quotation marks during registration, enabling the Windows Service Control Manager to misinterpret spaces in the path. By strategically placing a malicious executable with a crafted name (e.g., `Program.exe`) within the `C:\Program Files\` directory, an attacker can trick the operating system into executing their arbitrary code with elevated permissions during service startup, gaining full control over the compromised host.

## Attack Chain

1.  An attacker gains local user access to a system running Matrix42 Remote Control Host.
2.  The attacker identifies that the `FastViewerRemoteService` or `FastViewerRemoteProxy` services are configured with an unquoted service path, such as `C:\Program Files\Matrix42\Remote Control Host\FastViewerRemoteService.exe`.
3.  The attacker crafts a malicious executable, for instance, `Program.exe`, designed to perform unauthorized actions (e.g., create a new user, install a backdoor, deploy additional malware).
4.  The attacker places this `Program.exe` file into the `C:\Program Files\` directory, which is often writable by standard users, especially within certain subdirectories or older Windows versions.
5.  The attacker waits for a system reboot, forces a service restart (if permissions allow), or waits for an administrative action that triggers a restart of the vulnerable service.
6.  During service startup, the Windows Service Control Manager attempts to locate and execute the service binary. Due to the unquoted path, it first interprets `C:\Program.exe` as the intended executable.
7.  The malicious `C:\Program.exe` is executed instead of the legitimate service binary, inheriting SYSTEM privileges due to the service's configuration.
8.  The attacker achieves SYSTEM-level privilege escalation, enabling full control over the compromised host for further malicious activities, such as data exfiltration, lateral movement, or persistent access.

## Impact

The successful exploitation of CVE-2016-20095 grants a local attacker SYSTEM-level privileges on the compromised system. This is a critical escalation that allows complete control over the operating system, including the ability to install rootkits, disable security software, exfiltrate sensitive data, or establish persistent access. While specific victim counts are not available, any organization utilizing vulnerable versions of Matrix42 Remote Control Host is at risk of complete system compromise if a local attacker gains a foothold. The vulnerability's age indicates that unpatched systems could still be prevalent, posing a significant risk.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM and tune for your environment to detect `C:\Program.exe` process creation and file creation in `C:\Program Files\`.
*   Monitor for process creation events (`process_creation` log source) where `Program.exe` is executed from the `C:\Program Files\` directory with SYSTEM privileges.
*   Monitor for file creation events (`file_event` log source) of `Program.exe` within the `C:\Program Files\` directory.
*   Patch Matrix42 Remote Control Host to a version greater than 3.20.0031 as advised by the vendor on `https://www.matrix42.com/`.
