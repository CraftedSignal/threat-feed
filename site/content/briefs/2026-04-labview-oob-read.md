---
title: NI LabVIEW Out-of-Bounds Read Vulnerability (CVE-2026-32864)
slug: 2026-04-labview-oob-read
description: A memory corruption vulnerability exists in NI LabVIEW due to an out-of-bounds read in mgcore_SH_25_3!aligned_free(), potentially leading to information disclosure or arbitrary code execution if a user opens a specially crafted VI file.
date: "2026-04-08T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-32864
  - labview
  - memory-corruption
  - out-of-bounds-read
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2026-32864
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32864
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/memory-corruption-vulnerabilities-in-ni-labview.html
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: LabVIEW Suspicious VI File Open
    description: Detects the opening of LabVIEW VI files from unusual locations, potentially indicating a malicious file.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: LabVIEW Suspicious Child Process
    description: Detects LabVIEW spawning unusual child processes, indicating potential code execution from a malicious VI file.
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

A memory corruption vulnerability, identified as CVE-2026-32864, exists within National Instruments (NI) LabVIEW software. The flaw is triggered by an out-of-bounds read within the `mgcore_SH_25_3!aligned_free()` function. An attacker can exploit this vulnerability by enticing a user to open a specially crafted VI (Virtual Instrument) file. Successful exploitation could lead to information disclosure, potentially exposing sensitive data handled by LabVIEW, or arbitrary code execution, granting the attacker control over the affected system. This vulnerability affects NI LabVIEW versions 2026 Q1 (26.1.0) and all prior versions, making a wide range of LabVIEW installations susceptible.

## Attack Chain

1. An attacker crafts a malicious LabVIEW VI file designed to trigger the out-of-bounds read in `mgcore_SH_25_3!aligned_free()`.
2. The attacker uses social engineering to convince a victim to open the specially crafted VI file.
3. The victim opens the malicious VI file using a vulnerable version of NI LabVIEW (2026 Q1 (26.1.0) and prior).
4. LabVIEW attempts to process the malformed data within the VI file.
5. The `mgcore_SH_25_3!aligned_free()` function is called during the VI file processing.
6. The out-of-bounds read occurs when `aligned_free()` attempts to access memory outside of allocated bounds.
7. Depending on the memory layout, this can lead to information disclosure by leaking memory contents, or arbitrary code execution by overwriting critical data.
8. If arbitrary code execution is achieved, the attacker can then install malware, exfiltrate data, or perform other malicious actions on the compromised system.

## Impact

Successful exploitation of CVE-2026-32864 can have serious consequences. Information disclosure could expose sensitive data processed by LabVIEW, such as measurement data, control algorithms, or proprietary code. Arbitrary code execution would allow an attacker to gain complete control over the affected system, enabling them to install malware, steal data, or disrupt operations. The vulnerability affects a broad range of LabVIEW users, potentially impacting industrial control systems, research and development environments, and other critical applications.

## Recommendation

*   Apply the patch provided by National Instruments for CVE-2026-32864 to remediate the out-of-bounds read vulnerability. Refer to the NI security advisory for specific instructions.
*   Deploy the Sigma rule `LabVIEW_Suspicious_VI_File_Open` to detect suspicious LabVIEW VI files being opened based on file path or other attributes.
*   Monitor process creation events for `LabVIEW.exe` spawning unusual child processes or accessing unusual network resources after a VI file has been opened, which could indicate successful code execution (see `LabVIEW_Suspicious_Child_Process` rule).
*   Educate users about the risks of opening untrusted VI files and emphasize the importance of verifying the source of any VI file before opening it.
