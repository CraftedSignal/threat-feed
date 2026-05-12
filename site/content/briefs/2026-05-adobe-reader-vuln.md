---
title: Adobe Acrobat Reader Vulnerability Allows Information Disclosure and Code Execution
slug: 2026-05-adobe-reader-vuln
description: A local attacker can exploit a vulnerability in Adobe Acrobat Reader to disclose sensitive information and execute arbitrary code, potentially leading to a complete system compromise.
date: "2026-05-12T21:08:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - code-execution
  - information-disclosure
vendors:
  - Adobe
products:
  - Acrobat Reader
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1047
rules:
  - title: Detect Suspicious Acrobat Reader Child Processes
    description: Detects Acrobat Reader spawning suspicious child processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Acrobat Reader Spawning cmd.exe
    description: Detects Acrobat Reader spawning cmd.exe which is often indicative of exploitation.
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

A vulnerability exists in Adobe Acrobat Reader that allows a local attacker to disclose sensitive information and execute arbitrary code. The successful exploitation of this vulnerability could lead to a complete compromise of the affected system. The vulnerability allows attackers with local access to potentially escalate privileges and execute malicious code within the context of the application. This can be achieved by crafting a malicious PDF document or leveraging a flaw in the application's handling of specific file formats or operations. Defenders should focus on monitoring for suspicious file access and process creation events originating from Adobe Acrobat Reader.

## Attack Chain

1. The attacker gains local access to the target system through social engineering or other means.
2. The attacker crafts a malicious PDF document designed to exploit the vulnerability in Adobe Acrobat Reader.
3. The attacker lures the victim into opening the malicious PDF document using Adobe Acrobat Reader.
4. Upon opening the PDF, the vulnerability is triggered, allowing the attacker to execute arbitrary code.
5. The attacker escalates privileges within the system using the code execution vulnerability.
6. The attacker leverages the gained privileges to access sensitive information stored on the system.
7. The attacker installs malware or establishes persistence for future access.
8. The attacker achieves complete system compromise, potentially leading to data exfiltration or further malicious activities.

## Impact

Successful exploitation of this vulnerability allows a local attacker to disclose sensitive information and execute arbitrary code. This could lead to a complete compromise of the system, potentially resulting in data loss, data theft, or the installation of malware. The vulnerability affects all users of Adobe Acrobat Reader who have local access to a vulnerable system.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Acrobat Reader Child Processes` to your SIEM and tune for your environment.
*   Deploy the Sigma rule `Detect Acrobat Reader Spawning cmd.exe` to your SIEM and tune for your environment.
