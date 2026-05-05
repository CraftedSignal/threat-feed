---
title: Registry Modification to Disable .NET ETW Logging
slug: 2024-01-dotnet-etw-disable
description: Attackers may modify the Windows registry to disable ETW logging for the .NET Framework, hindering endpoint detection and response capabilities.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - etw
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3
  - https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/
  - https://attack.mitre.org/techniques/T1562/006/
rules:
  - title: Detect Dotnet ETW Disabled Via Registry
    description: Detects changes to the COMPlus_ETWEnabled registry value to disable .NET ETW logging
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.006
    data_sources:
      - registry_set
      - windows
  - title: Detect Registry Modification via Command Line
    description: Detects command-line usage of reg.exe to modify registry values.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1547.001
      - T1562.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to disable Event Tracing for Windows (ETW) for the .NET Framework to evade detection by security tools. This involves modifying the `COMPlus_ETWEnabled` registry value to disable .NET ETW logging, preventing security products from monitoring .NET-based threats. The registry value is located under the "Environment" registry key path for both user (HKCU\Environment) and machine (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment) scopes. Disabling ETW allows attackers to operate undetected, potentially leading to further compromise and persistent access within the environment. This technique has been observed across various threat actors aiming to evade EDR solutions, making it a critical concern for defenders.

## Attack Chain

1. The attacker gains initial access to the system, potentially through phishing or exploitation of a vulnerability.
2. The attacker escalates privileges to obtain administrative rights.
3. The attacker identifies the registry key `HKCU\Environment` or `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.
4. The attacker modifies the `COMPlus_ETWEnabled` registry value to `0` or `0x00000000`. This can be achieved through tools like `reg.exe` or PowerShell.
5. The system processes the registry change, effectively disabling .NET ETW logging.
6. The attacker executes malicious .NET code without generating ETW logs.
7. The attacker performs lateral movement and other malicious activities, evading detection.
8. The attacker achieves their final objective, such as data exfiltration or ransomware deployment.

## Impact

Successful disabling of .NET ETW logging can severely limit the visibility of security tools into malicious activities, allowing attackers to operate undetected. This can lead to prolonged compromises, data breaches, and ransomware infections. The impact is widespread as it affects any organization relying on .NET ETW for security monitoring. Disabling ETW could bypass many endpoint detection and response (EDR) solutions that rely on this logging, potentially impacting thousands of organizations.

## Recommendation

*   Enable Sysmon EventID 13 to monitor registry modifications, as this is the primary data source for detecting the described activity.
*   Deploy the Sigma rule `Detect Dotnet ETW Disabled Via Registry` to your SIEM and tune for your environment.
*   Investigate any changes to the `COMPlus_ETWEnabled` registry value, especially if initiated by unusual processes.
*   Monitor for command-line arguments used to modify registry keys via `reg.exe` or PowerShell, using the Sigma rule `Detect Registry Modification via Command Line`.
*   Ensure that your Sysmon configuration is up to date and includes the necessary registry monitoring configurations.
