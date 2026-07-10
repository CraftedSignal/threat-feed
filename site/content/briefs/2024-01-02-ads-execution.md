---
title: Unusual Process Execution via Alternate Data Streams
slug: 2024-01-02-ads-execution
description: Adversaries may use Alternate Data Streams (ADS) to hide malicious executables and execute them, evading traditional detection methods by concealing the file's true nature.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - malware
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_unusual_dir_ads.toml
  - https://attack.mitre.org/techniques/T1564/
  - https://attack.mitre.org/techniques/T1564/004/
rules:
  - title: Process Execution from Alternate Data Stream
    description: Detects processes executing directly from an Alternate Data Stream (ADS).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.004
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Execution from Alternate Data Stream
    description: Detects PowerShell executing directly from an Alternate Data Stream (ADS).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers leverage Alternate Data Streams (ADS) within the NTFS file system to conceal malicious code and executables. By storing executables within the ADS of seemingly benign files, attackers can bypass security measures that rely on standard file analysis. This technique, actively used in the wild, involves executing processes directly from the ADS, making it difficult to detect via conventional methods. This behavior has been observed across multiple attack vectors and affects all versions of the Windows operating system. Detecting this activity is critical as it signifies a deliberate attempt to evade security controls and potentially execute malicious code within the environment.

## Attack Chain

1.  An attacker gains initial access to the system through various means (e.g., phishing, exploitation of vulnerabilities).
2.  The attacker uploads or creates a malicious executable.
3.  The attacker uses a tool or script (e.g., `cmd.exe`, PowerShell) to write the malicious executable into an Alternate Data Stream (ADS) of an existing file (e.g., `type evil.exe > legitimate.txt:evil.exe`).
4.  The attacker executes the hidden malicious executable from the ADS using `cmd.exe` or PowerShell. For example: `cmd.exe /c start legitimate.txt:evil.exe`.
5.  The executed malicious code performs its intended actions, such as establishing persistence, downloading additional payloads, or performing lateral movement.
6.  The attacker attempts to maintain stealth by deleting the originally dropped malicious file or further obfuscating their actions within the compromised system.
7.  The attacker achieves their objective, which could include data exfiltration, system compromise, or establishing a persistent foothold.

## Impact

A successful attack leveraging Alternate Data Streams can lead to complete system compromise, data theft, and potential disruption of services. While the number of affected victims is not explicitly stated, this technique can be employed in targeted attacks against organizations in any sector. The primary impact is the circumvention of standard security controls, allowing malware to operate undetected for extended periods.

## Recommendation

*   Deploy the Sigma rule "Process Execution from Alternate Data Stream" to your SIEM to detect processes spawned from ADS paths and tune for your environment.
*   Enable Sysmon process creation logging to capture process execution details, which are required for the Sigma rules above.
*   Investigate any process executions with command-line arguments matching the pattern "?:\\*:*" in your environment, as highlighted in the rule description.
*   Review parent-child process relationships for processes executing from Alternate Data Streams to identify the source of the malicious execution.
