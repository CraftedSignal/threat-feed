---
title: Splinterware System Scheduler Pro 5.12 Privilege Escalation via Insecure Permissions (CVE-2018-25359)
slug: 2026-05-splinterware-privilege-escalation
description: Splinterware System Scheduler Pro 5.12 is vulnerable to privilege escalation (CVE-2018-25359) due to insecure file permissions, allowing low-privilege users to replace the service executable with a malicious one, leading to arbitrary code execution as LocalSystem.
date: "2026-05-26T14:13:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - cve
vendors:
  - Splinterware
products:
  - System Scheduler Pro (5.12)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2018-25359
    cvss: 8.4
    epss: 0.00012
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25359
  - https://www.exploit-db.com/exploits/45072
  - https://www.splinterware.com
  - https://www.vulncheck.com/advisories/splinterware-system-scheduler-pro-privilege-escalation
rules:
  - title: Detect CVE-2018-25359 Exploitation - WService.exe Replacement
    description: Detects CVE-2018-25359 exploitation — Creation of WService.exe by a non-SYSTEM process, indicating potential service executable replacement.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: File Integrity Monitoring - Splinterware Service Executable
    description: Monitors file modifications to the Splinterware System Scheduler Pro service executable, WService.exe.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Splinterware System Scheduler Pro version 5.12 is susceptible to a privilege escalation vulnerability (CVE-2018-25359). This flaw stems from insecure file permissions associated with the service executable. A low-privilege user can exploit this vulnerability to gain elevated privileges on the system. The attack involves replacing the legitimate service executable with a malicious one. When the System Scheduler Pro service starts, it executes the replaced malicious executable with LocalSystem privileges, granting the attacker complete control over the compromised system. This vulnerability poses a significant risk to organizations using the affected software.

## Attack Chain

1.  A low-privilege user gains access to the target system.
2.  The user identifies the installation directory of Splinterware System Scheduler Pro 5.12.
3.  The user renames the legitimate `WService.exe` file within the installation directory.
4.  The user copies a malicious executable file to the installation directory.
5.  The user renames the malicious executable to `WService.exe`, effectively replacing the original service executable.
6.  The user triggers the Splinterware System Scheduler Pro service to start.
7.  The operating system executes the malicious `WService.exe` with LocalSystem privileges.
8.  The attacker gains complete control of the compromised system.

## Impact

Successful exploitation of CVE-2018-25359 allows a low-privilege user to escalate their privileges to LocalSystem. This grants the attacker complete control over the affected system, enabling them to install malware, steal sensitive data, modify system configurations, or disrupt critical services. The vulnerability affects version 5.12 of Splinterware System Scheduler Pro.

## Recommendation

*   Monitor for file modifications in the Splinterware System Scheduler Pro installation directory, specifically the `WService.exe` executable. Use the file integrity monitoring rule to detect unauthorized changes.
*   Deploy the provided Sigma rule to detect the creation of `WService.exe` by non-system processes.
*   Restrict write access to the Splinterware System Scheduler Pro installation directory to prevent low-privilege users from modifying the `WService.exe` file.
*   Consider upgrading or migrating away from Splinterware System Scheduler Pro 5.12 as there are no official patches available from the vendor.
