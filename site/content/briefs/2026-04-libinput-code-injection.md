---
title: Libinput Code Injection Vulnerability via Malicious Lua Bytecode (CVE-2026-35093)
slug: 2026-04-libinput-code-injection
description: A local attacker can exploit CVE-2026-35093 in libinput by placing a specially crafted Lua bytecode file in configuration directories, allowing arbitrary code execution with the privileges of the application using libinput.
date: "2026-04-01T14:16:57Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - libinput
  - code-injection
  - lua
  - cve-2026-35093
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: 'Command and Scripting Interpreter: Visual Basic Script'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087.001
    technique_name: 'Account Discovery: Local Account'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
cves:
  - id: CVE-2026-35093
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35093
  - https://access.redhat.com/security/cve/CVE-2026-35093
  - https://bugzilla.redhat.com/show_bug.cgi?id=2453839
  - https://gitlab.freedesktop.org/libinput/libinput/-/work_items/1271
rules:
  - title: Detect Suspicious Lua Bytecode File Creation
    description: Detects the creation of potentially malicious Lua bytecode files in common configuration directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505
    data_sources:
      - file_event
      - linux
  - title: Detect Libinput Process Monitoring Keyboard Input
    description: Detects libinput or related processes attempting to read keyboard input via /dev/input.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1056.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Network Connections from Compositor Processes
    description: Detects network connections initiated by compositor processes which could indicate data exfiltration.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

CVE-2026-35093 describes a code injection vulnerability within the libinput library. This flaw allows a local attacker with the ability to write files to specific system or user configuration directories to bypass security restrictions. By placing a maliciously crafted Lua bytecode file in these directories, an attacker can inject and execute arbitrary code. The injected code runs with the same privileges as the application using libinput, often a graphical compositor. This vulnerability was reported on April 1, 2026, and impacts systems where libinput is used to handle input devices. Successful exploitation can lead to significant compromise of the affected system, allowing attackers to perform actions such as keylogging or further escalating privileges.

## Attack Chain

1.  The attacker gains initial access to the target system with the ability to write files to the filesystem.
2.  The attacker identifies a system or user configuration directory that libinput reads Lua bytecode files from.
3.  The attacker crafts a malicious Lua bytecode file designed to execute arbitrary code. This file exploits the vulnerability in libinput's bytecode parsing.
4.  The attacker places the malicious Lua bytecode file into the identified configuration directory.
5.  The graphical compositor or other application using libinput loads and parses the malicious Lua bytecode file.
6.  The vulnerability in libinput is triggered, causing the malicious code within the bytecode file to be executed.
7.  The attacker's code executes with the same privileges as the application using libinput, gaining control over the compositor.
8.  The attacker leverages the elevated privileges to monitor keyboard input, potentially stealing credentials or other sensitive information, and exfiltrates data to an external server.

## Impact

Successful exploitation of CVE-2026-35093 allows a local attacker to execute arbitrary code with elevated privileges. This can lead to the compromise of sensitive data, such as keystrokes and credentials, as well as the potential for further system compromise. Given that libinput is used by many graphical compositors and other applications that handle input devices, a successful attack could impact a large number of systems. The impact includes data theft, privilege escalation, and the installation of persistent backdoors.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Lua Bytecode File Creation` to identify the creation of suspicious Lua bytecode files in configuration directories (logsource: `file_event`, rule title: `Detect Suspicious Lua Bytecode File Creation`).
*   Monitor file creation events in libinput configuration directories for files with the `.lua` extension using file integrity monitoring tools.
*   Apply any available patches for libinput to address CVE-2026-35093 as soon as they are released.
