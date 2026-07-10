---
title: PowerShell Manual Base64 Decoding Implementation
slug: 2024-01-manual-base64-powershell
description: This detection identifies Windows PowerShell processes implementing manual Base64 decoding, a technique used by threat actors to obfuscate malicious payloads and evade standard detection mechanisms.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - base64
  - obfuscation
  - defense-evasion
vendors:
  - Microsoft
products:
  - PowerShell
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.virustotal.com/gui/file/4b3ab4d9f2332da6b6cd8d9d0f4910a5eb85ac8c969108acb3ad49631812f998/behavior
iocs:
  - type: url
    value: https://www.virustotal.com/gui/file/4b3ab4d9f2332da6b6cd8d9d0f4910a5eb85ac8c969108acb3ad49631812f998/behavior
ioc_counts:
  url: 1
rules:
  - title: Detect PowerShell Manual Base64 Decoding via Substring
    description: Detects PowerShell processes that use Substring and other string manipulation methods for Base64 decoding.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.010
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Manual Base64 Decoding via Bitwise Operators
    description: Detects PowerShell processes using bitwise operators indicative of manual Base64 decoding.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.010
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors often use Base64 encoding to obfuscate malicious payloads or commands within PowerShell scripts. By manually decoding Base64 strings, attackers can evade detection mechanisms that look for standard decoding functions like using the "-enc" flag or the "FromBase64String" function. This detection focuses on PowerShell processes that exhibit characteristics of manual Base64 decoding, such as the presence of specific string manipulation methods and bitwise operations. Security teams should investigate any instances of such activity, especially if found in conjunction with other suspicious behaviors or on systems that should not be using PowerShell for such tasks. Defenders should prioritize monitoring for PowerShell execution coupled with unusual string manipulation and bitwise operations.

## Attack Chain

1. Initial Access: An attacker gains initial access to a Windows system, often through phishing or exploiting a vulnerability.
2. PowerShell Execution: The attacker launches PowerShell, a powerful scripting language native to Windows.
3. Obfuscation: The attacker uses Base64 encoding to hide malicious code or commands within the PowerShell script.
4. Manual Decoding Implementation: Instead of using built-in Base64 decoding functions, the attacker implements a custom Base64 decoder within the PowerShell script using string manipulation methods (e.g., `Substring`, `IndexOf`, `GetString`) and bitwise operations (e.g., `-shl`, `-shr`, `-bxor`, `-bor`, `-band`).
5. Payload Reconstruction: The custom decoder processes the Base64 encoded string, reconstructing the original malicious payload or command.
6. Execution: The reconstructed payload or command is then executed within the PowerShell context. This could involve downloading additional malware, modifying system configurations, or exfiltrating sensitive data.
7. Persistence (Optional): The attacker may establish persistence by creating scheduled tasks or modifying registry keys to ensure continued access to the system.
8. Objectives Achieved: The attacker successfully executes their malicious objectives, such as data theft, system compromise, or lateral movement within the network.

## Impact

Successful exploitation can lead to the execution of arbitrary code, potentially resulting in data theft, system compromise, or further lateral movement within the network. Systems with sensitive data or critical functions are at higher risk. While the exact number of victims is unknown, the widespread use of PowerShell in enterprise environments makes this a potentially significant threat.

## Recommendation

*   Deploy the Sigma rule `Detect PowerShell Manual Base64 Decoding via Substring` to your SIEM and tune for your environment (see rule below).
*   Deploy the Sigma rule `Detect PowerShell Manual Base64 Decoding via Bitwise Operators` to your SIEM and tune for your environment (see rule below).
*   Investigate any PowerShell processes exhibiting manual Base64 decoding behaviors by reviewing command-line arguments and process ancestry to identify potential malicious intent, referencing the attack chain described above.
*   Monitor PowerShell execution logs (Sysmon EventID 1 and Windows Event Log Security 4688) for suspicious string manipulation and bitwise operations within PowerShell scripts to identify potential manual Base64 decoding implementations.
*   Block the URL `https://www.virustotal.com/gui/file/4b3ab4d9f2332da6b6cd8d9d0f4910a5eb85ac8c969108acb3ad49631812f998/behavior` if your organization's security policy prohibits access to malware analysis sites or if you identify repeated attempts to access this URL from your network.
