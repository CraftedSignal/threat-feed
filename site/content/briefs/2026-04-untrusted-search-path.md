---
title: 'CVE-2026-3780: Local Privilege Escalation via Untrusted Search Path in Application Installer'
slug: 2026-04-untrusted-search-path
description: An application installer vulnerable to CVE-2026-3780 runs with elevated privileges but resolves system executables and DLLs using an untrusted search path, enabling local privilege escalation by allowing a local attacker to inject malicious binaries.
date: "2026-04-01T02:16:03Z"
severities:
  - high
type: advisory
types:
  - advisory
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

CVE-2026-3780 describes a local privilege escalation vulnerability affecting an application installer. The installer, when executed, operates with elevated privileges. However, it resolves the location of system executables and DLLs using an untrusted search path. This untrusted path includes directories writable by standard users. An attacker can exploit this by placing malicious binaries, named identically to legitimate system files, in these user-writable directories. When the installer attempts to load or execute these system files, the attacker's malicious versions are used instead, due to the flawed search path resolution. This leads to arbitrary code execution with elevated privileges, thereby escalating the attacker's privileges on the local system. This vulnerability was reported in Foxit products and poses a significant risk to systems where the vulnerable installer is executed.

## Attack Chain

1.  The attacker identifies a user-writable directory included in the application installer's search path.
2.  The attacker analyzes the application installer to determine which system executables or DLLs it attempts to load or execute.
3.  The attacker creates malicious binaries that mimic the names of the targeted system files.
4.  The attacker places the malicious binaries into the user-writable directory.
5.  The attacker executes the vulnerable application installer, typically requiring some user interaction (e.g., clicking "Install").
6.  The installer, running with elevated privileges, attempts to load or execute the legitimate system files.
7.  Due to the untrusted search path, the installer loads or executes the attacker's malicious binaries instead of the legitimate ones.
8.  The attacker's code executes with elevated privileges, allowing the attacker to perform actions such as creating new accounts, installing software, or modifying system settings, thereby achieving local privilege escalation.

## Impact

Successful exploitation of CVE-2026-3780 allows a local attacker to gain elevated privileges on the system. This means an attacker with limited access can perform administrative tasks, install malware, access sensitive data, and potentially compromise the entire system. The severity is high because it bypasses normal security controls and can lead to a full system compromise from a limited starting point. This poses a significant risk to any system running the affected application installer.

## Recommendation

*   Deploy the Sigma rule "Detect DLL Hijacking via Installer" to detect the creation of malicious DLLs in user-writable directories, referencing the rule details below.
*   Enable file creation monitoring in user-writable directories (e.g., %TEMP%, %APPDATA%) to provide data for the Sigma rule and to detect suspicious file activity.
*   Monitor process creation events for the execution of unexpected binaries within the context of the application installer, leveraging the rule "Detect Suspicious Process Execution by Installer" defined below.
