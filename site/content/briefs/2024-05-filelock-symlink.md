---
title: CVE-2025-68146 filelock TOCTOU Race Condition Enables Symlink Attacks
slug: 2024-05-filelock-symlink
description: CVE-2025-68146 describes a Time-of-Check Time-of-Use (TOCTOU) race condition vulnerability in the filelock library that could allow for symlink attacks during lock file creation, potentially leading to unauthorized file access or modification.
date: "2026-04-29T07:50:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - TOCTOU
  - symlink
  - filelock
  - CVE-2025-68146
  - race condition
vendors:
  - Microsoft
cves:
  - id: CVE-2025-68146
    cvss: 6.3
    epss: 4e-05
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-68146
rules:
  - title: Detect Suspicious Symlink Creation
    description: Detects the creation of symbolic links by non-standard processes, which could indicate an attempt to exploit a TOCTOU vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - process_creation
      - linux
  - title: Detect File Access via Symlink
    description: Detects file access events where the accessed file is a symbolic link, potentially indicating malicious activity leveraging symlinks.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2025-68146 is a security vulnerability residing within the filelock library, a widely used Python library for file locking. The vulnerability stems from a Time-of-Check Time-of-Use (TOCTOU) race condition that occurs during the creation of lock files. This weakness can be exploited by a local attacker to perform symlink attacks. By carefully manipulating the file system, an attacker can potentially redirect the lock creation process to a file location they control. This is a locally exploitable vulnerability with potential for privilege escalation and unauthorized access, but requires local access to the vulnerable system. The advisory was published on April 29, 2026.

## Attack Chain

1.  Attacker gains initial local access to the system.
2.  Attacker identifies an application utilizing the vulnerable filelock library for file locking operations.
3.  Attacker creates a symbolic link (symlink) pointing the expected lock file path to a file location under their control.
4.  The vulnerable application attempts to create a lock file at the expected location.
5.  Due to the TOCTOU race condition, between the time the application checks for the existence of the lock file and the time it attempts to create it, the symlink is followed.
6.  The lock file is created in the attacker-controlled location instead of the intended secure location.
7.  The application continues execution, believing it has exclusive access, while the attacker can potentially modify or access the protected resource.

## Impact

Successful exploitation of CVE-2025-68146 allows an attacker to manipulate file locking mechanisms, potentially leading to unauthorized modification or access to sensitive files. This can lead to data corruption, privilege escalation, or denial of service. The vulnerability requires local access, limiting the scope of potential attacks, but can be a critical issue in multi-user environments or systems with sensitive data.

## Recommendation

*   Apply patches or updates provided by the vendor (Microsoft) to address CVE-2025-68146 when they become available.
*   Implement file integrity monitoring to detect unauthorized modifications to critical files and directories.
*   Deploy the Sigma rule provided below to detect suspicious symlink creation attempts that might indicate exploitation of this TOCTOU vulnerability.
