---
title: CVE-2026-32175 .NET Core Tampering Vulnerability
slug: 2026-05-dotnet-tampering-vuln
description: A tampering vulnerability exists in .NET 8.0, .NET 9.0, and .NET 10.0 due to improper handling of specially crafted files, potentially allowing an attacker to write arbitrary files and directories to specific locations on a vulnerable system with limited control over the destination.
date: "2026-05-18T19:08:39Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - tampering
  - dotnet
vendors:
  - Microsoft
products:
  - .NET 8.0
  - .NET 9.0
  - .NET 10.0
  - Microsoft.NetCore.App.Runtime.win-arm
  - Microsoft.NetCore.App.Runtime.win-arm64
  - Microsoft.NetCore.App.Runtime.win-x64
  - Microsoft.NetCore.App.Runtime.win-x86
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32175
    cvss: 4.3
    epss: 0.00078
references:
  - https://github.com/advisories/GHSA-rg75-q538-x34v
  - https://www.cve.org/CVERecord?id=CVE-2026-32175
rules:
  - title: Detects CVE-2026-32175 exploitation - Suspicious File Creation by .NET Process
    description: Detects CVE-2026-32175 exploitation - Monitors file creation events by .NET processes outside of standard application directories, potentially indicating exploitation of the tampering vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
  - title: Detects CVE-2026-32175 exploitation - .NET Process Writing to Unusual Locations
    description: Detects CVE-2026-32175 exploitation - Detects .NET processes writing files to unusual locations which can indicate exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Microsoft has released a security advisory regarding a tampering vulnerability, CVE-2026-32175, affecting .NET 8.0, .NET 9.0, and .NET 10.0. The vulnerability stems from .NET Core's improper handling of specially crafted files. Successful exploitation could allow an attacker to write arbitrary files and directories to specific locations on a vulnerable system. However, the attacker's control over the destination of these files and directories is limited. To exploit this vulnerability, an attacker must send a specially crafted file to a vulnerable system. The advisory provides guidance for developers to update their applications to remediate this vulnerability.

## Attack Chain

1. An attacker crafts a malicious file designed to exploit the .NET Core tampering vulnerability.
2. The attacker transmits the specially crafted file to a system running a vulnerable version of .NET Core (8.0, 9.0, or 10.0).
3. The vulnerable .NET Core application processes the malicious file without proper validation.
4. Due to the improper file handling, the attacker gains the ability to write files and directories to the system.
5. The attacker attempts to write malicious files to locations where they can be executed or used for further exploitation.
6. While the attacker's control over the exact destination is limited, they can potentially overwrite existing files or create new ones in accessible directories.
7. If the attacker successfully writes executable files, they can achieve code execution on the system.
8. The attacker leverages the code execution to perform malicious activities, such as data exfiltration or system compromise.

## Impact

Successful exploitation of CVE-2026-32175 allows an attacker to write arbitrary files and directories on a vulnerable system. While the attacker's control over the write destination is limited, they can potentially overwrite existing files or create new ones in accessible directories. This can lead to code execution, data exfiltration, or further system compromise. The vulnerability affects applications using .NET 8.0, .NET 9.0, and .NET 10.0 on Windows platforms.

## Recommendation

*   Immediately upgrade to the latest versions of .NET 8.0, .NET 9.0, and .NET 10.0 to patch CVE-2026-32175, as described in the Microsoft advisory.
*   For applications referencing the vulnerable packages, update the package references to the patched versions (e.g., update Microsoft.NetCore.App.Runtime.win-* to versions 8.0.27, 9.0.16, or 10.0.8).
*   Recompile and redeploy self-contained applications targeting the impacted .NET versions, as the deployed applications are also vulnerable.
*   Deploy the Sigma rule targeting file creation events associated with .NET processes to detect potential exploitation attempts.
