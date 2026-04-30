---
title: Adobe Acrobat Reader Prototype Pollution Vulnerability (CVE-2026-34622)
slug: 2026-04-acrobat-prototype-pollution
description: A prototype pollution vulnerability in Adobe Acrobat Reader versions 26.001.21411, 24.001.30360, 24.001.30362 and earlier (CVE-2026-34622) allows for arbitrary code execution when a user opens a specially crafted malicious file.
date: "2026-04-15T12:00:00Z"
type: advisory
types:
  - advisory
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

On April 14, 2026, CVE-2026-34622 was published, detailing a prototype pollution vulnerability affecting Adobe Acrobat Reader. The vulnerability impacts versions 26.001.21411, 24.001.30360, 24.001.30362 and earlier. Successful exploitation of this vulnerability could allow an attacker to execute arbitrary code in the context of the current user. The attack requires user interaction, specifically the opening of a malicious PDF file within the vulnerable Acrobat Reader application. This can lead to compromise of the user's system and potentially further lateral movement within the network, making it a significant risk for organizations.

## Attack Chain

1.  Attacker crafts a malicious PDF file designed to exploit the prototype pollution vulnerability (CVE-2026-34622).
2.  The malicious PDF is delivered to the victim via email or other file-sharing mechanisms.
3.  The victim opens the malicious PDF file using a vulnerable version of Adobe Acrobat Reader.
4.  The malicious PDF exploits the prototype pollution vulnerability to modify object prototype attributes within Acrobat Reader's JavaScript engine.
5.  The modification of prototype attributes allows the attacker to inject malicious JavaScript code.
6.  The injected JavaScript code executes arbitrary commands within the context of the user running Acrobat Reader.
7.  The arbitrary code can be used to download and execute a secondary payload, such as malware, or steal sensitive data.
8.  The attacker gains control of the user's system and can perform actions such as data exfiltration or further exploitation of the network.

## Impact

Successful exploitation of CVE-2026-34622 can lead to arbitrary code execution on a victim's machine. This can result in the installation of malware, data exfiltration, or further compromise of the network. Given the widespread use of Adobe Acrobat Reader across various sectors, a successful campaign exploiting this vulnerability could have a broad impact, potentially affecting numerous users and organizations.

## Recommendation

*   Patch Adobe Acrobat Reader to a version beyond 26.001.21411, 24.001.30360, and 24.001.30362 to remediate CVE-2026-34622.
*   Deploy the Sigma rule `AcrobatReaderSuspiciousFileOpen` to detect suspicious process execution originating from Acrobat Reader.
*   Monitor network connections originating from Acrobat Reader for any unusual or unexpected outbound traffic using `AcrobatReaderOutboundConnection`.
