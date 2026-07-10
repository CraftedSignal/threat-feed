---
title: Microsoft Office Use-After-Free Vulnerability CVE-2026-32190
slug: 2024-01-office-uaf
description: CVE-2026-32190 is a use-after-free vulnerability in Microsoft Office that allows an unauthorized attacker to execute code locally.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - use-after-free
  - microsoft-office
  - code-execution
  - cve-2026-32190
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Word
  - Excel
  - PowerPoint
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053.005
    technique_name: 'Scheduled Task/Job: Scheduled Task'
cves:
  - id: CVE-2026-32190
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32190
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32190
rules:
  - title: Detect Suspicious Process Creation from Office Applications
    description: Detects suspicious process creation events originating from Microsoft Office applications, which could indicate exploitation of CVE-2026-32190.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053.005
      - T1059.001
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Office Application Spawning Unusual Network Connection
    description: Detects network connections initiated by Office applications to uncommon ports or IPs, indicative of potential command and control activity after CVE-2026-32190 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32190 is a critical use-after-free vulnerability affecting Microsoft Office. This vulnerability allows an attacker with local access to execute arbitrary code on a vulnerable system. The vulnerability arises from improper memory management within the Office suite, potentially impacting various applications like Word, Excel, and PowerPoint. Successful exploitation could lead to complete system compromise, including data theft, modification, or destruction. Microsoft has assigned a CVSS v3.1 score of 8.4, highlighting the high potential impact. Defenders should prioritize patching this vulnerability to prevent potential exploitation. The specific versions of Microsoft Office affected are not detailed in the source, but the CVE was published on 2026-04-14.

## Attack Chain

1.  The attacker gains initial access to the target system, potentially through social engineering or physical access.
2.  The attacker crafts a malicious Office document (e.g., Word, Excel, PowerPoint) specifically designed to trigger the use-after-free vulnerability. This involves manipulating the document's internal structure to cause memory corruption.
3.  The attacker convinces the victim to open the malicious Office document. This could be achieved via email, shared network drives, or other means.
4.  When the victim's Office application processes the malicious document, the use-after-free vulnerability is triggered.
5.  The application attempts to access a memory location that has already been freed, leading to a crash or unexpected behavior.
6.  The attacker leverages this memory corruption to inject and execute arbitrary code within the context of the Office application.
7.  The attacker's code gains control of the system and can perform malicious actions such as installing malware, stealing data, or creating new user accounts.
8.  The attacker achieves their objective, such as data exfiltration, ransomware deployment, or lateral movement within the network.

## Impact

Successful exploitation of CVE-2026-32190 can lead to complete system compromise. An attacker can gain full control over the affected machine, potentially leading to data theft, data corruption, or malware installation. Given the widespread use of Microsoft Office, this vulnerability poses a significant risk to both individuals and organizations. The lack of details on the number of victims or sectors targeted in the source emphasizes the need for proactive patching and detection measures.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-32190 immediately after release (reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32190).
*   Deploy the Sigma rules provided below to your SIEM to detect potential exploitation attempts.
*   Enable process creation logging on endpoints to provide the necessary data for the Sigma rules to function.
*   Monitor for suspicious process execution originating from Microsoft Office applications.
