---
title: Potential PowerShell Obfuscated Script via High Entropy
slug: 2024-01-09-powershell-obfuscation
description: This rule detects potential PowerShell obfuscated scripts by identifying script blocks with high entropy and non-uniform character distributions, which attackers use to evade signature-based detections.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - obfuscation
  - defense_evasion
  - windows
vendors:
  - Microsoft
products:
  - Microsoft Windows
  - Microsoft PowerShell
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_posh_high_entropy.toml
  - https://attack.mitre.org/techniques/T1027/
  - https://attack.mitre.org/techniques/T1027/010/
  - https://attack.mitre.org/techniques/T1140/
rules:
  - title: Detect Obfuscated PowerShell Script via High Entropy
    description: Detects PowerShell script blocks with high entropy, a common characteristic of obfuscated scripts used to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.010
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Script with Surprisal Deviation
    description: Detects PowerShell scripts with non-uniform character distributions, potentially indicating obfuscation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.010
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often obfuscate PowerShell scripts using encoding, encryption, or compression to evade signature-based detections and hinder manual analysis. This technique allows malicious actors to hide their code's true intent, making it difficult for security analysts to identify and understand the script's behavior. This detection identifies PowerShell script blocks with high entropy and non-uniform character distributions, characteristics that are common in obfuscated scripts. The rule focuses on statistical anomalies in PowerShell script blocks. It checks for large script blocks (over 1000 characters) with high entropy (>= 5.5 bits) and significant surprisal standard deviation (> 0.7). Note that legitimate scripts can trigger this alert when they embed packed data (e.g., compressed resources).

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2. The attacker uploads or creates a PowerShell script on the target system.
3. The PowerShell script is obfuscated using techniques such as Base64 encoding, gzip compression, or encryption algorithms.
4. The obfuscated script is executed via `powershell.exe`.
5. The script decodes, decrypts, or decompresses the malicious payload in memory.
6. The payload is executed, performing actions such as establishing persistence, downloading additional malware, or exfiltrating data.
7. The attacker leverages the established foothold for lateral movement within the network.
8. The final objective is achieved (e.g., data theft, ransomware deployment).

## Impact

Successful obfuscation allows attackers to bypass traditional signature-based security controls. This can lead to undetected malware infections, data breaches, and system compromise. The impact includes potential data theft, system disruption, and financial loss. While the number of victims and specific sectors targeted are unknown, the widespread use of PowerShell makes this a broadly applicable threat.

## Recommendation

*   Enable PowerShell Script Block Logging to generate the necessary events (4104) for this detection. Reference: [https://ela.st/powershell-logging-setup](https://ela.st/powershell-logging-setup)
*   Deploy the Sigma rule "Detect Obfuscated PowerShell Script via High Entropy" to your SIEM and tune the threshold values (`powershell.file.script_block_length`, `powershell.file.script_block_entropy_bits`, `powershell.file.script_block_surprisal_stdev`) to match your environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on execution context, script content, and initiating source as detailed in the rule's description.
*   Review `file.path` (if present) to determine the script's origin and legitimacy.
*   Implement endpoint detection and response (EDR) solutions to monitor for post-execution activity, such as suspicious network connections and file modifications.
*   Block execution of PowerShell scripts from unusual file directories (user-writable or temporary locations).
