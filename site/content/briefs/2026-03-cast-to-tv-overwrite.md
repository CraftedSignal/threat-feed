---
title: UXGROUP Cast to TV Screen Mirroring Arbitrary File Overwrite Vulnerability (CVE-2026-30282)
slug: 2026-03-cast-to-tv-overwrite
description: UXGROUP LLC Cast to TV Screen Mirroring v2.2.77 is vulnerable to arbitrary file overwrite (CVE-2026-30282) via the file import process, allowing attackers to overwrite critical internal files and potentially achieve arbitrary code execution or information exposure.
date: "2026-03-31T18:16:47Z"
severities:
  - critical
tags:
  - arbitrary-file-overwrite
  - code-execution
  - information-disclosure
  - cve-2026-30282
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-30282
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30282
  - http://cast.com
  - https://appcraze.co/
  - https://github.com/Secsys-FDU/AF_CVEs/issues/27
  - https://secsys.fudan.edu.cn/
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious File Import Overwrite
    description: Detects potential arbitrary file overwrite attempts during file import operations by monitoring for unusual file creation or modification events in sensitive directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious File Import Process
    description: Detects potential arbitrary file overwrite attempts based on unusual process execution related to the Cast to TV application's file import process.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-30282 describes an arbitrary file overwrite vulnerability affecting UXGROUP LLC's Cast to TV Screen Mirroring version 2.2.77. This vulnerability exists within the application's file import functionality. An attacker with the ability to supply a malicious file through the import process can overwrite critical internal application files. Successful exploitation can lead to arbitrary code execution within the context of the application or the exposure of sensitive information stored…
