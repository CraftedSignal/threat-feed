---
title: Microsoft Excel Out-of-Bounds Read Vulnerability (CVE-2026-32188)
slug: 2026-04-excel-oob-read
description: An out-of-bounds read vulnerability in Microsoft Office Excel (CVE-2026-32188) allows a local attacker to potentially disclose sensitive information through a maliciously crafted Excel file.
date: "2026-04-15T12:00:00Z"
severities:
  - medium
tags:
  - excel
  - out-of-bounds read
  - cve-2026-32188
  - information disclosure
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-32188
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32188
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32188
rules:
  - title: Detect Suspicious Excel Process Creation
    description: Detects Excel spawning child processes, which can be indicative of exploitation or macro execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Excel Opening Network Connections
    description: Detects Excel making network connections, which may be a sign of malicious macro execution or exploitation.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32188 describes an out-of-bounds read vulnerability affecting Microsoft Office Excel. According to the NVD, this vulnerability allows an unauthorized attacker to disclose information locally. The CVSS v3.1 score is 7.1, indicating a high severity. The vulnerability resides within how Excel parses certain file formats, potentially allowing a malicious actor to craft a file that, when opened, causes Excel to read memory outside of allocated buffers. This can lead to the disclosure of…
