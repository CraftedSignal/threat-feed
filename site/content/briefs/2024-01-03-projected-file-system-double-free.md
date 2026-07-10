---
title: Windows Projected File System Double Free Vulnerability (CVE-2026-32069)
slug: 2024-01-03-projected-file-system-double-free
description: CVE-2026-32069 is a double free vulnerability in the Windows Projected File System that allows an authorized local attacker to elevate privileges.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-32069
  - privilege-escalation
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32069
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32069
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32069
rules:
  - title: Detect Projected File System API Usage
    description: Detects processes using specific Projected File System APIs, which could be an early indicator of exploitation.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential Double Free Trigger - Unusual File Operations in ProjFS
    description: Detects unusual file system operations within the Projected File System that could indicate an attempt to trigger the double-free vulnerability.
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

CVE-2026-32069 is a critical vulnerability affecting the Windows Projected File System. This double-free vulnerability allows an attacker with local access and authorization to escalate their privileges. The vulnerability exists within the core functionality of the Projected File System, a feature designed to allow applications to virtualize files and directories. The vulnerability was published on 2026-04-14. Successful exploitation of this flaw could grant an attacker elevated rights on the system, potentially leading to full system compromise. This vulnerability is of significant concern for defenders as it allows for local privilege escalation.

## Attack Chain

1.  Attacker gains initial local access to a Windows system. This might involve social engineering, physical access, or exploiting another vulnerability to obtain a low-privileged account.
2.  The attacker leverages the Projected File System API to create a virtualized file system. This involves specific API calls to initialize and configure the projection.
3.  The attacker triggers the double-free condition within the Projected File System by manipulating specific file system operations (e.g., creating, deleting, or modifying files in the projected file system). The precise operations needed to trigger the vulnerability are specific to the implementation flaw.
4.  The first "free" operation deallocates a memory region associated with a file system object within the Projected File System.
5.  The attacker crafts memory allocation requests to influence the memory layout and place controlled data at the location of the previously freed memory.
6.  The second "free" operation attempts to deallocate the same memory region again, leading to memory corruption.
7.  The memory corruption allows the attacker to overwrite critical system data structures, such as process tokens or access control lists.
8.  The attacker elevates their privileges by exploiting the corrupted memory to gain SYSTEM-level access.

## Impact

Successful exploitation of CVE-2026-32069 allows a local attacker to escalate privileges on a vulnerable Windows system. This could allow the attacker to install programs; view, change, or delete data; or create new accounts with full user rights. Given the nature of privilege escalation vulnerabilities, the impact is severe.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-32069 as soon as possible. (Reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32069)
*   Monitor for suspicious process creation events related to file system operations, especially involving the Projected File System, using a process creation rule.
*   Enable auditing of file system events to detect suspicious activity within the Projected File System.
