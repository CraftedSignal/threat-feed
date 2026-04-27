---
title: Libinput Code Injection Vulnerability via Malicious Lua Bytecode (CVE-2026-35093)
slug: 2026-04-libinput-code-injection
description: A local attacker can exploit CVE-2026-35093 in libinput by placing a specially crafted Lua bytecode file in configuration directories, allowing arbitrary code execution with the privileges of the application using libinput.
date: "2026-04-01T14:16:57Z"
severities:
  - high
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

CVE-2026-35093 describes a code injection vulnerability within the libinput library. This flaw allows a local attacker with the ability to write files to specific system or user configuration directories to bypass security restrictions. By placing a maliciously crafted Lua bytecode file in these directories, an attacker can inject and execute arbitrary code. The injected code runs with the same privileges as the application using libinput, often a graphical compositor. This vulnerability was…
