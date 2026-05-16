---
title: Syncplify.me Server! Unquoted Service Path Vulnerability (CVE-2020-37230)
slug: 2026-05-syncplify-unquoted-service-path
description: Syncplify.me Server! version 5.0.37 contains an unquoted service path vulnerability (CVE-2020-37230) in the SMWebRestServicev5 service, allowing a local attacker to escalate privileges by placing a malicious executable in the service path.
date: "2026-05-16T16:18:07Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - unquoted-service-path
  - privilege-escalation
  - windows
vendors:
  - Syncplify
products:
  - Syncplify.me Server! 5.0.37
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2020-37230
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37230
rules:
  - title: Detect Unquoted Service Path Exploitation - Executable Created
    description: Detects CVE-2020-37230 exploitation — Creation of an executable file in a potential unquoted service path directory. This may indicate an attempt to exploit the vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Unquoted Service Path - SMWebRestServicev5 Service
    description: Detects CVE-2020-37230 exploitation — Creation of an executable file pretending to be a directory of the Syncplify service.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Syncplify.me Server! version 5.0.37 is vulnerable to an unquoted service path vulnerability, identified as CVE-2020-37230. This flaw resides in the SMWebRestServicev5 service. A local attacker can exploit this vulnerability to escalate privileges on the system. The vulnerability occurs because the service's executable path is not enclosed in quotes, allowing an attacker to insert a malicious executable into a directory within the service path. When the service restarts, or the system reboots, this malicious executable will be executed with LocalSystem privileges, leading to a privilege escalation. This vulnerability allows attackers with local access to gain complete control over the affected system.

## Attack Chain

1.  Attacker gains local access to the target system.
2.  Attacker identifies the unquoted service path for the SMWebRestServicev5 service.
3.  Attacker creates a malicious executable file named after a directory in the service path. For example, if the service path is `C:\Program Files\Syncplify.me\SMWebRestServicev5.exe`, the attacker can create a file at `C:\Program.exe`.
4.  Attacker places the malicious executable in the directory that corresponds to the first part of the unquoted service path.
5.  Attacker waits for the system to reboot or the service to restart.
6.  The operating system attempts to start the SMWebRestServicev5 service, but due to the unquoted path, it executes the malicious executable with LocalSystem privileges.
7.  The malicious executable performs actions with elevated privileges, such as creating new user accounts, installing backdoors, or disabling security controls.
8.  Attacker achieves persistent access and control over the system with LocalSystem privileges.

## Impact

Successful exploitation of this vulnerability allows a local attacker to escalate privileges to LocalSystem. This provides the attacker with complete control over the compromised system. An attacker can install programs, view, change, or delete data, and create new accounts with full user rights. This vulnerability poses a significant risk to organizations using the affected Syncplify.me Server! version, potentially leading to data breaches, system compromise, and financial loss.

## Recommendation

*   Apply appropriate access controls to prevent unauthorized local access to systems running Syncplify.me Server! 5.0.37.
*   Implement the "Unquoted Service Path" Sigma rule to detect potential exploitation attempts by monitoring for executable files created in directories within unquoted service paths.
*   Manually audit service configurations to identify and remediate any other unquoted service paths in the environment.
*   Upgrade to a patched version of Syncplify.me Server! that addresses the CVE-2020-37230 vulnerability when available.
