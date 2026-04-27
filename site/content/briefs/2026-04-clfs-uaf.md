---
title: 'CVE-2026-32070: Windows CLFS Driver Use-After-Free Privilege Escalation'
slug: 2026-04-clfs-uaf
description: A use-after-free vulnerability, CVE-2026-32070, exists in the Windows Common Log File System (CLFS) driver, enabling a locally authenticated attacker to escalate privileges on a vulnerable system.
date: "2026-04-14T18:17:07Z"
severities:
  - high
tags:
  - privilege-escalation
  - use-after-free
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32070
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32070
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32070
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious CLFS Driver Interaction
    description: Detects processes interacting with the CLFS driver (clfs.sys) from unusual locations, which may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect CLFS Log File Creation in Suspicious Locations
    description: Detects the creation of CLFS log files (.blf, .regtrans-ms) in unusual directories, potentially indicating malicious activity.
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

CVE-2026-32070 is a critical use-after-free vulnerability residing within the Windows Common Log File System (CLFS) driver. This flaw allows an attacker with local access and valid credentials to potentially elevate their privileges on the system. Exploitation requires specific knowledge of the CLFS driver's internal workings to trigger the vulnerability. While the exact details of exploitation are not publicly available beyond the vulnerability description, the high CVSS score indicates the…
