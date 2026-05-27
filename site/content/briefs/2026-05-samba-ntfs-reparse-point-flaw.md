---
title: Samba NTFS Reparse Point Vulnerability (CVE-2026-1933)
slug: 2026-05-samba-ntfs-reparse-point-flaw
description: CVE-2026-1933 describes a vulnerability in Samba's handling of NTFS-style reparse points on read-only shares, allowing authenticated users with filesystem write permissions to modify reparse point metadata and potentially alter SMB-visible file behavior.
date: "2026-05-27T14:19:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - cve-2026-1933
  - samba
  - reparse point
  - privilege escalation
  - smb
vendors:
  - Red Hat
  - Samba
products:
  - Samba
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-1933
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1933
  - https://access.redhat.com/security/cve/CVE-2026-1933
  - https://bugzilla.redhat.com/show_bug.cgi?id=2447317
  - https://bugzilla.samba.org/show_bug.cgi?id=15992
rules:
  - title: Detect Samba Reparse Point Manipulation on Read-Only Shares
    description: Detects CVE-2026-1933 exploitation -- Attempts to create or modify NTFS reparse points on Samba shares configured as read-only.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious File Attribute Modification via SMB
    description: Detects suspicious modification of file attributes via SMB, which can be related to CVE-2026-1933 exploitation.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-1933 identifies a flaw in Samba's handling of NTFS-style reparse points. Specifically, on Samba shares configured with `read only = yes`, a missing SMB-layer access check allows authenticated users who possess underlying filesystem write permissions to manipulate reparse point metadata. This vulnerability enables such users to create or delete reparse points, even on exports that are intended to be read-only. The vulnerability was published on 2026-05-27 and affects Samba implementations utilizing NTFS-style reparse points. This can lead to unauthorized modification of file behavior visible over SMB, including the conversion of files into symbolic links or other reparse point types, potentially disrupting file access and integrity.

## Attack Chain

1.  Attacker authenticates to a Samba share configured with `read only = yes`.
2.  Attacker identifies a file or directory suitable for reparse point manipulation.
3.  Attacker uses SMB protocols to send a request to create a new NTFS-style reparse point or modify an existing one.
4.  Samba server receives the SMB request and processes it.
5.  Due to missing SMB-layer access checks, the request bypasses the read-only restriction if the user has underlying filesystem write permissions.
6.  Samba modifies the reparse point metadata on the underlying filesystem.
7.  The target file or directory's behavior is altered, potentially becoming a symbolic link or another reparse point type.
8.  Subsequent SMB clients accessing the modified file or directory now encounter the altered behavior dictated by the reparse point, potentially leading to unauthorized access or denial-of-service conditions.

## Impact

Successful exploitation of CVE-2026-1933 allows an authenticated attacker to modify the behavior of files and directories within a Samba share, even if the share is configured as read-only. This can lead to data corruption, unauthorized access, or denial-of-service. While the specific number of affected installations is unknown, any organization using Samba with read-only shares and NTFS-style reparse points may be vulnerable. The impact can range from minor inconvenience to significant disruption of file services, depending on the types of files and directories affected.

## Recommendation

*   Apply the appropriate patches or updates provided by Samba to address CVE-2026-1933 as soon as they are available.
*   Review Samba share configurations to ensure that users with write access to the underlying filesystem are appropriately restricted at the SMB layer.
*   Monitor Samba logs for suspicious activity related to reparse point creation or modification.
*   Deploy the Sigma rule `Detect Samba Reparse Point Manipulation on Read-Only Shares` to detect potential exploitation attempts.
*   Implement file integrity monitoring on critical Samba shares to detect unauthorized changes to file metadata.
