---
title: Microsoft Office Excel Use-After-Free Vulnerability (CVE-2026-32198)
slug: 2026-04-excel-use-after-free
description: CVE-2026-32198 is a use-after-free vulnerability in Microsoft Office Excel that allows an attacker to execute code locally on a vulnerable system.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - use-after-free
  - excel
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-32198
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32198
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32198
rules:
  - title: Detect Excel Opening Files From Suspicious Locations
    description: Detects Microsoft Excel opening files from temporary or download locations, which may indicate a socially engineered attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Excel Child Processes
    description: Detects Microsoft Excel spawning suspicious child processes, potentially indicating code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Excel Writing Executables to Disk
    description: Detects Microsoft Excel writing executable files to disk, which may be indicative of malware being dropped.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CVE-2026-32198 is a critical use-after-free vulnerability affecting Microsoft Office Excel. Discovered and reported on April 14, 2026, this vulnerability allows an unauthenticated, local attacker to execute arbitrary code on a target system. The vulnerability stems from improper memory management within Excel while processing malformed or specially crafted Excel files. Successful exploitation of this flaw could lead to complete system compromise, allowing attackers to install malware, steal sensitive data, or pivot to other systems within the network. This vulnerability impacts systems running vulnerable versions of Microsoft Office Excel.

## Attack Chain

1. An attacker crafts a malicious Excel file designed to trigger the use-after-free vulnerability.
2. The attacker delivers the malicious Excel file to the victim via social engineering.
3. The victim opens the malicious Excel file using a vulnerable version of Microsoft Office Excel.
4. Excel attempts to access a memory location that has already been freed, triggering the vulnerability.
5. The attacker gains control of the execution flow due to the use-after-free condition.
6. The attacker injects malicious code into the Excel process's memory space.
7. The injected code executes with the privileges of the user running Excel.
8. The attacker can install malware, steal data, or perform other malicious activities on the system.

## Impact

Successful exploitation of CVE-2026-32198 allows an attacker to execute arbitrary code on a vulnerable system. This can lead to complete system compromise, data theft, malware installation, and potentially further network compromise. Organizations that rely heavily on Excel for data processing and analysis are particularly at risk.

## Recommendation

*   Apply the security patch released by Microsoft to address CVE-2026-32198 on all systems running Microsoft Office Excel.
*   Deploy the Sigma rules in this brief to your SIEM to detect potential exploitation attempts of CVE-2026-32198.
*   Educate users about the risks of opening suspicious or unexpected Excel files delivered via email or other means.
