---
title: NI LabVIEW LVCLASS File Parsing Out-of-Bounds Write Vulnerability (CVE-2026-32861)
slug: 2026-04-labview-lvclass-oob-write
description: A memory corruption vulnerability exists in NI LabVIEW due to an out-of-bounds write when loading a corrupted LVCLASS file (CVE-2026-32861), potentially leading to information disclosure or arbitrary code execution if a user opens a specially crafted .lvclass file.
date: "2026-04-07T20:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-32861
  - labview
  - out-of-bounds write
  - memory corruption
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-32861
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32861
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-class-file-parsing-memory-corruption-vulnerability-in-ni-labview.html
rules:
  - title: Detect Suspicious Lvclass File Open
    description: Detects suspicious process opening LVCLASS files which may indicate exploitation of CVE-2026-32861
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect LabVIEW Process Creation Without Parent
    description: Detects LabVIEW process creation without a common parent process, potentially indicating suspicious activity.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A memory corruption vulnerability has been identified in NI LabVIEW versions 2026 Q1 (26.1.0) and prior. This vulnerability, tracked as CVE-2026-32861, stems from an out-of-bounds write that occurs when the software attempts to load a malformed LVCLASS file. An attacker could exploit this vulnerability by crafting a malicious .lvclass file and convincing a user to open it within LabVIEW. Successful exploitation of this vulnerability could allow an attacker to achieve arbitrary code execution or disclose sensitive information from the affected system. This poses a significant risk to organizations using LabVIEW for critical applications, as it could lead to system compromise and data breaches.

## Attack Chain

1.  The attacker crafts a malicious .lvclass file containing an out-of-bounds write payload.
2.  The attacker delivers the crafted .lvclass file to the victim via social engineering or other delivery methods.
3.  The victim, using a vulnerable version of NI LabVIEW, opens the malicious .lvclass file.
4.  LabVIEW attempts to parse the LVCLASS file, triggering the out-of-bounds write vulnerability.
5.  The out-of-bounds write corrupts memory, potentially overwriting critical data structures or code.
6.  If the overwritten memory contains attacker-controlled code, it could lead to arbitrary code execution.
7.  The attacker gains control of the LabVIEW process and potentially the entire system.
8.  The attacker performs malicious actions, such as data exfiltration, installing backdoors, or further compromising the system.

## Impact

Successful exploitation of CVE-2026-32861 can lead to information disclosure and arbitrary code execution on systems running vulnerable versions of NI LabVIEW. This could allow an attacker to steal sensitive data, install malware, or gain complete control of the affected system. The impact of this vulnerability is significant, especially for organizations using LabVIEW in critical infrastructure or industrial control systems, potentially leading to operational disruption, financial loss, and reputational damage.

## Recommendation

*   Apply the security patch provided by National Instruments to address CVE-2026-32861 on all systems running NI LabVIEW 2026 Q1 (26.1.0) and prior versions. Refer to the NI advisory for download links: [https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-class-file-parsing-memory-corruption-vulnerability-in-ni-labview.html](https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-class-file-parsing-memory-corruption-vulnerability-in-ni-labview.html).
*   Implement user awareness training to educate users about the risks of opening files from untrusted sources to mitigate the initial access vector.
*   Deploy the Sigma rule `DetectSuspiciousLvclassFileOpen` to detect suspicious LabVIEW process opening LVCLASS files.
