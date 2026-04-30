---
title: NTFS-3G Heap Buffer Overflow Vulnerability (CVE-2026-40706)
slug: 2026-04-ntfs3g-heap-overflow
description: A heap buffer overflow vulnerability exists in NTFS-3G versions 2022.10.3 before 2026.2.25 that allows for heap memory corruption by processing a crafted NTFS image with multiple ACCESS_DENIED ACEs containing WRITE_OWNER from distinct group SIDs.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ntfs-3g
  - heap-overflow
  - privilege-escalation
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40706
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40706
  - https://github.com/tuxera/ntfs-3g/security/advisories/GHSA-4cwv-5285-63v9
rules:
  - title: Detect NTFS-3G Crashes Related to ACL Processing
    description: Detects crashes of the ntfs-3g process that may be related to malformed ACL processing.  This is a heuristic approach and may require tuning.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
  - title: Detect ntfs-3g abnormal exit
    description: Detects ntfs-3g exiting with a non-zero exit code while attempting to access an NTFS volume. May indicate a corrupted NTFS image.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-40706 describes a heap buffer overflow vulnerability affecting NTFS-3G, specifically versions 2022.10.3 and earlier, before the patch in version 2026.2.25. The vulnerability lies within the `ntfs_build_permissions_posix()` function in `acls.c`. An attacker can exploit this flaw by creating a malicious NTFS image. When the affected software attempts to read this specially crafted image, a heap buffer overflow occurs. This is triggered when the software processes a security descriptor containing multiple ACCESS_DENIED Access Control Entries (ACEs), each including WRITE_OWNER permissions, and originating from distinct group Security Identifiers (SIDs). Successful exploitation allows an attacker to corrupt heap memory within the SUID-root ntfs-3g binary, potentially leading to privilege escalation or arbitrary code execution.

## Attack Chain

1.  Attacker crafts a malicious NTFS image containing a specially designed security descriptor.
2.  The security descriptor includes multiple ACCESS_DENIED ACEs.
3.  Each ACE within the descriptor contains WRITE_OWNER permissions.
4.  The ACEs originate from distinct group SIDs, triggering the overflow condition.
5.  The attacker delivers the malicious NTFS image to a system running a vulnerable version of NTFS-3G. This may occur through physical media or network shares.
6.  The victim system attempts to read the malicious NTFS image using a vulnerable NTFS-3G version, such as during a `stat`, `readdir`, or `open` operation.
7.  The `ntfs_build_permissions_posix()` function is called to process the security descriptor.
8.  The heap buffer overflow occurs during the processing of the malicious ACEs, corrupting heap memory. This can lead to denial of service or potentially arbitrary code execution.

## Impact

Successful exploitation of CVE-2026-40706 allows for heap memory corruption in the ntfs-3g binary, which runs with elevated privileges due to its SUID-root configuration. The observed consequence is memory corruption. Depending on the extent of the corruption, this could lead to denial-of-service or arbitrary code execution. Given the wide usage of NTFS-3G for mounting NTFS volumes on Linux and other systems, a successful exploit could affect a large number of systems.

## Recommendation

*   Upgrade NTFS-3G to version 2026.2.25 or later to patch CVE-2026-40706 (reference: <https://github.com/tuxera/ntfs-3g/releases/tag/2026.2.25>).
*   Monitor systems for unexpected crashes or errors related to ntfs-3g operations, which may indicate exploitation attempts. Deploy the Sigma rules below to your SIEM and tune for your environment.
*   Consider implementing stricter access controls and validation measures on NTFS images to prevent the use of malicious images (mitigation based on the vulnerability description).
