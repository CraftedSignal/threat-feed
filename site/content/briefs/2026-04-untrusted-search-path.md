---
title: 'CVE-2026-3780: Local Privilege Escalation via Untrusted Search Path in Application Installer'
slug: 2026-04-untrusted-search-path
description: An application installer vulnerable to CVE-2026-3780 runs with elevated privileges but resolves system executables and DLLs using an untrusted search path, enabling local privilege escalation by allowing a local attacker to inject malicious binaries.
date: "2026-04-01T02:16:03Z"
severities:
  - high
tags:
  - privilege-escalation
  - cve-2026-3780
  - untrusted-search-path
  - dll-hijacking
  - installer
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574.001
    technique_name: Hijack Execution Flow
cves:
  - id: CVE-2026-3780
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3780
  - https://www.foxit.com/support/security-bulletins.html
rules:
  - title: Detect DLL Hijacking via Installer
    description: Detects the creation of DLL files in user-writable directories, potentially indicating DLL hijacking attempts during installer execution.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574
      - T1574.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Execution by Installer
    description: Detects the execution of suspicious processes (cmd.exe, powershell.exe, etc.) as a child process of a running installer.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-3780 describes a local privilege escalation vulnerability affecting an application installer. The installer, when executed, operates with elevated privileges. However, it resolves the location of system executables and DLLs using an untrusted search path. This untrusted path includes directories writable by standard users. An attacker can exploit this by placing malicious binaries, named identically to legitimate system files, in these user-writable directories. When the installer…
