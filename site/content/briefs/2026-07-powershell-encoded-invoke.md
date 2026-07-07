---
title: Detection of Base64 Encoded PowerShell Invoke- Keywords
slug: 2026-07-powershell-encoded-invoke
description: This brief details the detection of Base64 encoded PowerShell `Invoke-` keywords in command lines, a common stealth technique leveraged by malware families such as Gootloader for initial access, execution, and subsequent payload delivery, enabling evasive command and control.
date: "2026-07-03T14:42:23Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Gootloader
tags:
  - powershell
  - obfuscation
  - evasion
  - gootloader
  - windows
  - execution
  - initial-access
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Users search for legitimate business documents online and are redirected to malicious websites via SEO poisoning techniques.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The victim executes the downloaded malicious .js file, often by double-clicking it, initiating the infection chain.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The .js file (or other initial dropper) launches a PowerShell process via mshta.exe or wscript.exe, executing a highly obfuscated, Base64-encoded command.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Detects UTF-8 and UTF-16 Base64 encoded powershell 'Invoke-' calls
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The decoded PowerShell script connects to attacker-controlled C2 infrastructure to fetch subsequent stage payloads or commands.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_base64_invoke.yml
  - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
rules:
  - title: PowerShell Base64 Encoded Invoke Keyword
    description: Detects UTF-8 and UTF-16 Base64 encoded powershell 'Invoke-' calls, commonly used for evasive execution of malicious scripts.
    platform: sigma
    severity: high
    tactics:
      - evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief focuses on the detection of Base64 encoded PowerShell command-line arguments that contain the `Invoke-` keyword, a prevalent obfuscation technique used by various malware families, including Gootloader. Threat actors frequently employ Base64 encoding to evade endpoint security solutions and conceal malicious PowerShell scripts used for initial execution, staging, and downloading additional payloads. This technique became widely recognized in campaigns like the Gootloader "SEO Poisoning" attacks, which began leveraging this method for stealthy execution of malicious JavaScript files that ultimately deploy encoded PowerShell. Detecting these patterns is critical as they often indicate an attempt to bypass traditional signature-based defenses and execute complex attack stages, leading to severe impacts like ransomware deployment or data exfiltration.

## Attack Chain

1.  **Initial Access (SEO Poisoning):** Users search for legitimate business documents online and are redirected to malicious websites via SEO poisoning techniques.
2.  **Malicious Download:** Victims are prompted to download a seemingly legitimate `.zip` archive containing a highly obfuscated `.js` file or an ISO image.
3.  **User Execution:** The victim executes the downloaded malicious `.js` file, often by double-clicking it, initiating the infection chain.
4.  **Obfuscated PowerShell Execution:** The `.js` file (or other initial dropper) launches a PowerShell process via `mshta.exe` or `wscript.exe`, executing a highly obfuscated, Base64-encoded command.
5.  **Encoded Script Decryption & Execution:** The Base64-encoded string, containing keywords like `Invoke-Expression` or `Invoke-Command`, is decoded and executed by PowerShell, establishing covert communication.
6.  **Command and Control (C2):** The decoded PowerShell script connects to attacker-controlled C2 infrastructure to fetch subsequent stage payloads or commands.
7.  **Payload Delivery:** Additional malware, such as the Gootloader loader, is downloaded and executed, which then often deploys further malicious implants like Cobalt Strike, IcedID, or various infostealers.
8.  **Impact:** The deployed malware performs its objectives, which can range from further network compromise, data exfiltration, or ransomware deployment.

## Impact

Attacks leveraging Base64 encoded PowerShell `Invoke-` keywords, particularly those involving Gootloader, can have severe consequences for victim organizations. Gootloader campaigns are known for their broad targeting across various sectors, distributing a wide array of follow-on malware. Successful exploitation can lead to complete network compromise, widespread data encryption via ransomware, significant data exfiltration, and the theft of credentials or sensitive information. The resulting disruption can incur substantial financial costs related to incident response, recovery, and potential regulatory fines.

## Recommendation

*   Deploy the `PowerShell Base64 Encoded Invoke Keyword` Sigma rule to your SIEM to detect suspicious encoded PowerShell activity.
*   Enable PowerShell script block logging and module logging on all Windows endpoints to gain visibility into the content of executed scripts.
*   Regularly review logs for any processes initiating PowerShell with Base64 encoded commands, specifically looking for `Invoke-` keywords in the decoded content.
*   Implement robust web filtering and email security solutions to block access to known malicious domains and prevent the delivery of malicious attachments associated with SEO poisoning campaigns.
