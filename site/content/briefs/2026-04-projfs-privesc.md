---
title: Windows Projected File System Buffer Over-Read Privilege Escalation (CVE-2026-26184)
slug: 2026-04-projfs-privesc
description: CVE-2026-26184 is a buffer over-read vulnerability in the Windows Projected File System (ProjFS) that allows a local attacker to elevate privileges.
date: "2026-04-14T18:16:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-26184
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26184
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26184
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26184
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious ProjFS Activity
    description: Detects potential exploitation attempts of CVE-2026-26184 by monitoring for unusual activity related to the ProjFS driver.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Potential Privilege Escalation via ProjFS
    description: Detects potential privilege escalation attempts related to ProjFS by monitoring for unusual process creations or kernel module loads after ProjFS activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-26184 is a high-severity vulnerability affecting the Windows Projected File System (ProjFS). This buffer over-read vulnerability allows an authenticated local attacker to elevate their privileges on a vulnerable system. Successful exploitation would grant the attacker higher-level access to the system, potentially enabling them to perform actions such as installing programs, viewing, changing, or deleting data, or creating new accounts with full user rights. The vulnerability was reported to Microsoft and assigned a CVSS v3.1 base score of 7.8, indicating a significant risk. Affected systems require patching to prevent potential exploitation.

## Attack Chain

1.  The attacker gains initial access to the system with low-level privileges.
2.  The attacker crafts a malicious file or directory structure designed to trigger the buffer over-read in ProjFS.
3.  The attacker interacts with the specially crafted file or directory through the Windows Projected File System. This interaction could involve accessing, modifying, or listing the contents of the projected file system.
4.  The ProjFS driver attempts to read data from a buffer using an incorrect size, resulting in a buffer over-read.
5.  The over-read allows the attacker to read adjacent memory locations.
6.  The attacker leverages the memory disclosure to overwrite critical system data or function pointers within the kernel.
7.  The attacker executes code with elevated privileges within the kernel context.
8.  The attacker gains complete control over the system.

## Impact

Successful exploitation of CVE-2026-26184 allows a local attacker to elevate privileges to SYSTEM, the highest level of privilege in Windows. This would grant the attacker complete control over the compromised system. There is currently no public information about real-world exploitation. Sectors at risk are broad, as Windows Projected File System is a core component in modern Windows operating systems.

## Recommendation

*   Apply the security update provided by Microsoft to patch CVE-2026-26184 as soon as possible. The patch can be found in the Microsoft Security Update Guide ([https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26184](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26184)).
*   Monitor for unusual file system activity, especially related to ProjFS, by deploying the Sigma rule `Detect Suspicious ProjFS Activity`.
*   Monitor for unexpected processes or kernel modules loading after the projected file system operations by deploying the Sigma rule `Detect Potential Privilege Escalation via ProjFS`.
