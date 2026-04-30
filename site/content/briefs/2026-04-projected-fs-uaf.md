---
title: 'CVE-2026-32078: Windows Projected File System Use-After-Free Elevation of Privilege'
slug: 2026-04-projected-fs-uaf
description: A use-after-free vulnerability, CVE-2026-32078, exists in the Windows Projected File System, allowing a locally authenticated attacker to escalate privileges.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-32078
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32078
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32078
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32078
rules:
  - title: Detect Potential CVE-2026-32078 Exploitation via Unusual ProjFS Child Processes
    description: Detects potential exploitation attempts of CVE-2026-32078 by monitoring for unusual child processes spawned by ProjFS.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1611
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential CVE-2026-32078 Exploitation via Unexpected Network Connections from ProjFS
    description: Detects potential exploitation attempts of CVE-2026-32078 by monitoring for network connections initiated by ProjFS.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1611
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32078 is a use-after-free vulnerability affecting the Windows Projected File System. This vulnerability allows a locally authenticated attacker to elevate their privileges on a vulnerable system. The vulnerability exists because the Projected File System improperly handles memory operations. Exploitation of this flaw allows an attacker to execute arbitrary code with elevated privileges. Successful exploitation requires an attacker to have valid credentials on the local system and the ability to execute code. Microsoft assigned a CVSS v3.1 score of 7.8 (HIGH) to this vulnerability. Organizations should apply the provided patch as soon as possible to mitigate the risk.

## Attack Chain

1.  The attacker gains initial access to the target system with valid local user credentials.
2.  The attacker executes a specially crafted application designed to interact with the Windows Projected File System.
3.  The crafted application triggers the use-after-free vulnerability by causing the Projected File System to access a memory location that has already been freed.
4.  This memory corruption allows the attacker to overwrite critical data structures within the kernel.
5.  The attacker manipulates these data structures to gain control of system execution flow.
6.  The attacker injects malicious code into a privileged process.
7.  The injected code executes with elevated privileges (SYSTEM).
8.  The attacker can now perform actions such as installing programs, viewing, changing, or deleting data, or creating new accounts with full user rights.

## Impact

Successful exploitation of CVE-2026-32078 allows a local attacker to elevate their privileges to SYSTEM. This grants the attacker complete control over the compromised system. The attacker can install malware, exfiltrate sensitive data, create new administrator accounts, and perform other malicious activities. This could lead to significant data loss, system downtime, and reputational damage. The vulnerability affects all Windows systems that include the Projected File System.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-32078 on all affected Windows systems, as referenced in the vulnerability details.
*   Monitor process creations for unusual or unexpected processes spawned by the Projected File System using the provided Sigma rule.
*   Implement application control solutions to restrict the execution of unauthorized or untrusted applications that could potentially exploit this vulnerability.
