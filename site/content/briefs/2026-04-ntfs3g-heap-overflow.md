---
title: NTFS-3G Heap Buffer Overflow Vulnerability (CVE-2026-40706)
slug: 2026-04-ntfs3g-heap-overflow
description: A heap buffer overflow vulnerability exists in NTFS-3G versions 2022.10.3 before 2026.2.25 that allows for heap memory corruption by processing a crafted NTFS image with multiple ACCESS_DENIED ACEs containing WRITE_OWNER from distinct group SIDs.
date: "2026-04-22T12:00:00Z"
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

CVE-2026-40706 describes a heap buffer overflow vulnerability affecting NTFS-3G, specifically versions 2022.10.3 and earlier, before the patch in version 2026.2.25. The vulnerability lies within the `ntfs_build_permissions_posix()` function in `acls.c`. An attacker can exploit this flaw by creating a malicious NTFS image. When the affected software attempts to read this specially crafted image, a heap buffer overflow occurs. This is triggered when the software processes a security descriptor…
