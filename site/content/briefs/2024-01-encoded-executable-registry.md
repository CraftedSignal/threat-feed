---
title: Encoded Executable Stored in the Registry
slug: 2024-01-encoded-executable-registry
description: This rule detects registry write modifications hiding encoded portable executables, indicative of adversary defense evasion by avoiding storing malicious content directly on disk.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry
  - windows
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_hide_encoded_executable_registry.toml
  - https://attack.mitre.org/techniques/T1027/
  - https://attack.mitre.org/techniques/T1027/013/
  - https://attack.mitre.org/techniques/T1112/
  - https://attack.mitre.org/techniques/T1140/
iocs:
  - type: registry
    value: TVqQAAMAAAAEAAAA*
ioc_counts:
  registry: 1
rules:
  - title: Encoded Executable Stored in Registry
    description: Detects registry modifications with encoded executable content, indicating potential defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027.013
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Registry Modification Containing Base64 Encoded Data
    description: Detects suspicious registry modifications containing Base64 encoded data, potentially used to hide malicious scripts or executables.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1112
      - T1140
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This detection identifies Windows Registry modifications used to conceal encoded portable executables, a tactic employed by adversaries to evade traditional disk-based detection mechanisms. The rule focuses on detecting registry entries with data strings that match known encoded executable patterns. This technique allows attackers to store malicious code within the registry, making it more difficult to detect using standard file-based scanning methods. The rule is designed to work with Elastic Defend, but also supports data from third-party EDR solutions, including CrowdStrike, Microsoft Defender XDR, and SentinelOne. The detection logic focuses on identifying registry entries with data resembling encoded executables.

## Attack Chain

1. An attacker gains initial access to the system (e.g., through compromised credentials or exploiting a vulnerability).
2. The attacker uses a command-line tool, such as PowerShell or cmd.exe, to interact with the registry.
3. The attacker encodes a malicious executable using tools like `certutil` or custom encoding scripts.
4. The attacker creates or modifies a registry key using `reg.exe` or PowerShell's `Set-ItemProperty` cmdlet.
5. The encoded executable is written to the registry key's data value. The data string often starts with "TVqQAAMAAAAEAAAA*".
6. The attacker uses another script or command to decode the executable from the registry.
7. The decoded executable is then executed in memory or written to disk for execution.
8. The attacker achieves their final objective, such as establishing persistence, escalating privileges, or deploying ransomware.

## Impact

Successful exploitation allows attackers to evade traditional disk-based security measures, enabling them to execute malicious code undetected. Attackers can use this technique to establish persistence, escalate privileges, or deploy malware, including ransomware. The rule helps defenders identify systems where this defense evasion technique is being employed.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect encoded executables stored in the registry.
*   Enable Sysmon registry event logging to provide the necessary data for the provided Sigma rules.
*   Investigate any alerts triggered by the Sigma rules to determine if the registry modification is malicious.
*   Use endpoint detection and response (EDR) tools to further analyze suspicious processes associated with the registry modifications.
*   Implement application control policies to prevent the execution of unauthorized executables, even if they are decoded from the registry.
