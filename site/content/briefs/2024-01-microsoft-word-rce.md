---
title: Microsoft Word RTF Heap Overflow Vulnerability (CVE-2023-21716)
slug: 2024-01-microsoft-word-rce
description: CVE-2023-21716 is a critical heap-based buffer overflow vulnerability in Microsoft Word 2016's RTF parser, triggered by a malformed RTF file, leading to remote code execution on Windows 7.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:microsoft:office:2019:*:*:*:*:macos:*:*
  - cpe:2.3:a:microsoft:office_long_term_servicing_channel:2021:*:*:*:*:macos:*:*
  - cpe:2.3:a:microsoft:office_online_server:2016:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office_web_apps:2013:sp1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_enterprise_server:2013:sp1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_enterprise_server:2016:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_foundation:2013:sp1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:-:*:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:-:language_pack:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:word:2013:sp1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:word:2013:sp1:*:*:rt:*:*:*
tags:
  - cve-2023-21716
  - rtf
  - heap overflow
  - remote code execution
vendors:
  - Microsoft
products:
  - Word 2016
affected_os:
  - Windows 7
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2023-21716
    cvss: 9.8
    epss: 0.91419
references:
  - https://sploitus.com/exploit?id=3548C225-1BF9-5372-B726-948D360BBECC&utm_source=rss&utm_medium=rss
  - https://github.com/JMousqueton/CVE-2023-21716
rules:
  - title: Microsoft Word Spawning Suspicious Child Process
    description: Detects Microsoft Word spawning suspicious child processes, which could indicate successful exploitation of CVE-2023-21716.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Microsoft Word Crash with Heap Corruption Exception
    description: Detects crashes of Microsoft Word with the heap corruption exception code c0000374, potentially indicating CVE-2023-21716 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - application
      - windows
rules_count: 2
---

CVE-2023-21716 is a heap-based buffer overflow vulnerability found in Microsoft Word 2016's RTF parser (specifically, in `wwlib.dll`). The vulnerability stems from improper bounds checking when parsing the `\fonttbl` tag within an RTF file, particularly when the tag contains an excessive number of font IDs (e.g., `\f###`). A specially crafted RTF file can trigger the overflow, leading to remote code execution (RCE) with the privileges of the victim user. The vulnerability affects Microsoft Word 2016 on Windows 7 and has a CVSS score of 9.8 (Critical). The attack vector involves delivering the malicious RTF file via email or a shared file location. This vulnerability poses a significant threat because it allows attackers to execute arbitrary code on a vulnerable system simply by enticing a user to open a malicious document.

## Attack Chain

1.  Attacker crafts a malicious RTF file containing an overly large `\fonttbl` section with many font IDs (`\f###`).
2.  The attacker sends the malicious RTF file to the victim via email attachment or shared network drive.
3.  The victim opens the RTF file using Microsoft Word 2016 on Windows 7.
4.  Microsoft Word attempts to parse the `\fonttbl` section of the RTF file using the `wwlib.dll` library.
5.  Due to the excessive number of font IDs, the bounds check fails, resulting in a heap-based buffer overflow in `wwlib.dll`.
6.  The overflow overwrites critical data on the heap, leading to memory corruption.
7.  The application crashes with an exception code `c0000374` (heap corruption).
8.  The attacker leverages the heap overflow to execute arbitrary code within the context of the Microsoft Word process, achieving remote code execution.

## Impact

Successful exploitation of CVE-2023-21716 allows an attacker to execute arbitrary code on a vulnerable Windows 7 system running Microsoft Word 2016. This can lead to a complete compromise of the system, including data theft, malware installation, and further lateral movement within the network. The vulnerability has a CVSS score of 9.8 (Critical), reflecting its high severity and potential for widespread impact. While specific victim counts are unavailable, the broad use of Microsoft Word makes this vulnerability a significant risk.

## Recommendation

*   Although Windows 7 is EOL, consider the following actions if you must continue to support it.
*   Monitor process creation events for Microsoft Word (`WINWORD.EXE`) spawning unusual child processes, indicative of successful code execution, and deploy the "Microsoft Word Spawning Suspicious Child Process" Sigma rule.
*   Enable process auditing on systems running Microsoft Word and review logs for crashes related to `wwlib.dll` or exception code `c0000374`.
*   Consider blocking RTF files delivered via email at the email gateway. This can prevent the initial attack vector.
