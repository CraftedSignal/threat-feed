---
title: PowerShell Invoke-NinjaCopy Script Detection
slug: 2024-01-09-invoke-ninjacopy
description: The Invoke-NinjaCopy PowerShell script is used by attackers to directly access volume files, such as NTDS.dit or registry hives, for credential dumping.
date: "2024-01-09T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - powershell
  - ninjacopy
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/collection/Invoke-NinjaCopy.ps1
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_posh_invoke_ninjacopy.toml
rules:
  - title: Detect PowerShell Invoke-NinjaCopy Script Block Content
    description: Detects PowerShell script block content containing Invoke-NinjaCopy or related Stealth* functions.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Stealth Function Usage
    description: Detects PowerShell script block content containing StealthReadFile or StealthOpenFile functions.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Invoke-NinjaCopy is a PowerShell script used to perform direct volume file access, enabling attackers to bypass traditional file access controls. This technique allows reading locked system files, such as the NTDS.dit or registry hives, which are essential for credential dumping. The script, often incorporated into post-exploitation frameworks like Empire, leverages stealth functions to minimize detection. Defenders need to monitor PowerShell script block content for the presence of Invoke-NinjaCopy or related "Stealth*" functions to identify potential credential access attempts. This activity is typically observed in Windows environments where attackers attempt to escalate privileges or move laterally within a network. The use of NinjaCopy allows attackers to grab sensitive data without being blocked by standard security measures.

## Attack Chain

1. An attacker gains initial access to a Windows system, potentially through phishing or exploiting a vulnerability.
2. The attacker executes a PowerShell script, either directly or through a command-line interface.
3. The PowerShell script contains the Invoke-NinjaCopy function or related StealthReadFile, StealthOpenFile functions.
4. The script utilizes the StealthOpenFile function to directly access the volume where the target file resides (e.g., NTDS.dit).
5. StealthReadFile is used to read the contents of the target file, bypassing standard file access controls.
6. The script copies the contents of the NTDS.dit or registry hives to a temporary location.
7. The attacker dumps credentials from the copied NTDS.dit file using tools like secretsdump.py or other credential harvesting tools.
8. The attacker uses the harvested credentials to escalate privileges or move laterally within the network.

## Impact

Successful exploitation can lead to the compromise of domain credentials, granting the attacker access to sensitive information and systems. Credential dumping from NTDS.dit or registry hives can expose user accounts, service accounts, and other privileged credentials. The impact ranges from data breaches and financial losses to complete network compromise and disruption of services. If successful, attackers may gain persistent access and control over critical infrastructure, potentially affecting thousands of users and systems.

## Recommendation

*   Enable PowerShell Script Block Logging and monitor event ID 4104 for script content containing `Invoke-NinjaCopy`, `StealthReadFile`, `StealthOpenFile`, `StealthCloseFileDelegate` as described in the Overview.
*   Deploy the Sigma rule "PowerShell Invoke-NinjaCopy script" to your SIEM and tune the rule for false positives in your environment.
*   Investigate any PowerShell processes with command-line arguments that contain the identified keywords to identify potential attacker activity as outlined in the Attack Chain.
*   Implement strict access controls on sensitive files like `NTDS.dit` and registry hives to limit the impact of successful credential access attempts.
*   Review PowerShell execution policies to prevent the execution of unsigned or untrusted scripts.
