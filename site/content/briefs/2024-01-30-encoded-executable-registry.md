---
title: Encoded Executable Stored in the Registry
slug: 2024-01-30-encoded-executable-registry
description: This rule detects registry modifications used to hide encoded portable executables, indicating a defense evasion technique where adversaries avoid storing malicious content directly on disk by writing encoded executables to the Windows Registry.
date: "2024-01-30T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry-modification
  - encoded-executable
vendors:
  - Microsoft
products:
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
iocs:
  - type: string
    value: TVqQAAMAAAAEAAAA*
ioc_counts:
  string: 1
rules:
  - title: Encoded Executable Stored in the Registry (Sysmon)
    description: Detects registry write operations that store encoded executable data, a common technique for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.013
      - T1112
    data_sources:
      - registry_set
      - windows
  - title: Encoded Executable Stored in the Registry (Process Creation)
    description: Detects process creation events where the command line contains a registry query to read an encoded executable, followed by decoding and execution.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.013
      - T1112
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to evade defenses by storing encoded executable content within the Windows Registry. This technique avoids writing PE files directly to disk, which can be a trigger for many endpoint detection systems. This activity involves modifying registry keys to store Base64 or otherwise encoded executables, which are then later decoded and executed. The signature `TVqQAAMAAAAEAAAA*` is often observed as a prefix for encoded executables. This behavior is often incorporated into malware loaders, droppers, and other tools to conceal their true intent. The Elastic detection rule was published in 2020 and last updated in April 2026. This technique is relevant for defenders because it can bypass traditional file-based scanning and signature-based detection mechanisms.

## Attack Chain

1. An attacker gains initial access to the target system (e.g., via phishing or exploit).
2. The attacker executes a script or program (e.g., PowerShell or cmd.exe) to modify the registry.
3. The script writes an encoded executable (identified by the signature `TVqQAAMAAAAEAAAA*`) into a registry key value.
4. The attacker uses another script or program to read the encoded executable from the registry.
5. The script decodes the executable (e.g., using Base64 decoding).
6. The decoded executable is written to a temporary location in memory or on disk.
7. The attacker executes the decoded executable using process injection or other execution techniques.
8. The executed code performs malicious actions, such as establishing persistence, stealing credentials, or deploying ransomware.

## Impact

Successful exploitation allows attackers to conceal malicious code within the registry, evading traditional file-based detection methods. This can lead to prolonged compromise of the targeted system, enabling attackers to perform various malicious activities, including data theft, lateral movement, and deployment of ransomware. The number of victims and specific sectors targeted are dependent on the attacker's objectives.

## Recommendation

*   Deploy the "Encoded Executable Stored in the Registry" Sigma rule to detect suspicious registry modifications indicative of encoded executables being stored (rules).
*   Enable Sysmon registry event logging to ensure the required data is available for the provided Sigma rules (rules, logsource).
*   Investigate any registry modifications containing the encoded string `TVqQAAMAAAAEAAAA*` to identify potentially malicious activity (iocs).
*   Monitor process creation events for processes spawned from unusual locations or with unusual parent processes after registry modifications (rules).
