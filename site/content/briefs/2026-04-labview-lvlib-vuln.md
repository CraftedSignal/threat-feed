---
title: NI LabVIEW LVLIB File Parsing Memory Corruption Vulnerability (CVE-2026-32860)
slug: 2026-04-labview-lvlib-vuln
description: A memory corruption vulnerability exists in NI LabVIEW due to an out-of-bounds write when loading a corrupted LVLIB file, potentially leading to information disclosure or arbitrary code execution if a user opens a specially crafted .lvlib file.
date: "2026-04-07T20:16:24Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-32860
  - labview
  - memory corruption
  - out-of-bounds write
  - lvlib
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-32860
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32860
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-project-library-file-parsing-memory-corruption-vulnerability-in-ni-labview.html
iocs:
  - type: url
    value: https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-project-library-file-parsing-memory-corruption-vulnerability-in-ni-labview.html
ioc_counts:
  url: 1
rules:
  - title: Detect LabVIEW Opening Uncommon File Extensions
    description: Detects LabVIEW opening file extensions that are not typically associated with normal operation, which might indicate malicious LVLIB processing.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Uncommon Child Processes of LabVIEW
    description: Detects the creation of child processes from LabVIEW that are not commonly observed, which can be an indicator of code execution.
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

CVE-2026-32860 is a vulnerability affecting NI LabVIEW versions 2026 Q1 (26.1.0) and prior. The vulnerability stems from an out-of-bounds write condition encountered during the loading of a corrupted LVLIB (LabVIEW Library) file. An attacker could exploit this flaw by crafting a malicious .lvlib file and enticing a user to open it within LabVIEW. Successful exploitation could lead to memory corruption, potentially enabling information disclosure or the execution of arbitrary code within the context of the LabVIEW application. This poses a significant risk to systems running vulnerable versions of LabVIEW, particularly those handling or processing potentially untrusted LVLIB files.

## Attack Chain

1.  Attacker crafts a malicious .lvlib file containing corrupted data designed to trigger the out-of-bounds write.
2.  The attacker uses social engineering or other means to convince a victim to open the malicious .lvlib file in NI LabVIEW.
3.  The victim opens the .lvlib file within NI LabVIEW.
4.  LabVIEW attempts to parse the corrupted data within the .lvlib file.
5.  During the parsing process, the out-of-bounds write vulnerability is triggered due to the malformed data.
6.  Memory corruption occurs, potentially overwriting critical program data or code.
7.  Depending on the overwritten memory, the attacker may achieve information disclosure by reading sensitive data.
8.  Alternatively, the attacker may achieve arbitrary code execution by overwriting code pointers or injecting malicious code into memory.

## Impact

Successful exploitation of CVE-2026-32860 can lead to both information disclosure and arbitrary code execution on affected systems. An attacker exploiting this vulnerability could potentially gain unauthorized access to sensitive data processed or stored by LabVIEW, or completely compromise the affected system by executing malicious code. The impact is significant, especially in industrial control systems and other critical infrastructure environments where LabVIEW is commonly used, as it could lead to disruption of services, data breaches, or even physical damage.

## Recommendation

*   Apply the security patch provided by National Instruments as described in the advisory at [https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-project-library-file-parsing-memory-corruption-vulnerability-in-ni-labview.html](https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-project-library-file-parsing-memory-corruption-vulnerability-in-ni-labview.html) to remediate CVE-2026-32860.
*   Implement strict file handling procedures and user awareness training to prevent users from opening untrusted .lvlib files received from external sources.
*   Monitor process execution for unusual or unexpected activity originating from LabVIEW processes, which could indicate successful exploitation of this or other vulnerabilities.
