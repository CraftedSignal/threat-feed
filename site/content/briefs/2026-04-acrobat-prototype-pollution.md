---
title: Adobe Acrobat Reader Prototype Pollution Vulnerability (CVE-2026-34622)
slug: 2026-04-acrobat-prototype-pollution
description: A prototype pollution vulnerability in Adobe Acrobat Reader versions 26.001.21411, 24.001.30360, 24.001.30362 and earlier (CVE-2026-34622) allows for arbitrary code execution when a user opens a specially crafted malicious file.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-34622
  - adobe-acrobat
  - prototype-pollution
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-34622
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34622
  - https://helpx.adobe.com/security/products/acrobat/apsb26-44.html
rules:
  - title: AcrobatReaderSuspiciousFileOpen
    description: Detects suspicious file opens in Acrobat Reader that could be indicative of exploit attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: AcrobatReaderOutboundConnection
    description: Detects suspicious outbound network connections from Acrobat Reader, potentially indicating exploitation.
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

On April 14, 2026, CVE-2026-34622 was published, detailing a prototype pollution vulnerability affecting Adobe Acrobat Reader. The vulnerability impacts versions 26.001.21411, 24.001.30360, 24.001.30362 and earlier. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code in the context of the current user. The attack requires user interaction, specifically the opening of a malicious PDF file within the vulnerable Acrobat Reader application. This can lead…
