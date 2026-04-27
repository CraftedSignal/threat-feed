---
title: Adobe Photoshop Out-of-Bounds Read Vulnerability (CVE-2026-27289)
slug: 2026-04-photoshop-oob-read
description: An out-of-bounds read vulnerability (CVE-2026-27289) in Adobe Photoshop Desktop versions 27.4 and earlier allows for potential code execution via a crafted file, requiring user interaction to trigger the exploit.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-27289
  - out-of-bounds read
  - adobe photoshop
  - code execution
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-27289
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27289
  - https://helpx.adobe.com/security/products/photoshop/apsb26-40.html
ioc_counts:
  email: 2
rules:
  - title: Detect Photoshop Opening Files From Suspicious Locations
    description: Detects Photoshop opening files from locations commonly associated with downloads or temporary storage, which could indicate a user opening a malicious file.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Child Processes of Photoshop
    description: Detects the creation of suspicious child processes spawned by Photoshop, which could be indicative of code execution following an exploit.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adobe Photoshop Desktop versions 27.4 and earlier are vulnerable to an out-of-bounds read vulnerability (CVE-2026-27289). This flaw can be triggered when Photoshop parses a specially crafted file, leading to a read operation beyond the allocated memory boundary. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code within the security context of the user running the application. The vulnerability requires user interaction, as a victim must open a…
