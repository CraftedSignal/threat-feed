---
title: Detection of Windows Defender Service Disabling via Registry Modification
slug: 2024-01-disabling-defender-services
description: This brief covers the detection of adversaries disabling Windows Defender services by modifying specific registry keys to set the 'Start' value to '0x00000004', indicating an attempt to evade detection and maintain persistence.
date: "2024-01-03T18:22:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - windows
  - registry-abuse
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
rules:
  - title: Detect Disabling of Windows Defender Services via Registry Modification
    description: Detects the disabling of Windows Defender services by monitoring registry modifications where the 'Start' value is set to '0x00000004'.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    data_sources:
      - registry_set
      - windows
  - title: Detect Disabling of Windows Defender Services via Registry Modification - PowerShell
    description: Detects the disabling of Windows Defender services by monitoring registry modifications performed via PowerShell.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often disable Windows Defender services to evade detection and ensure the persistence of malware. This involves modifying specific registry keys that control the startup behavior of these services. By setting the 'Start' value to '0x00000004', the services are effectively disabled, preventing them from running automatically. This activity is a strong indicator of malicious intent, as it directly interferes with the endpoint's security mechanisms, leaving the system vulnerable to further compromise. The DFIR Report has documented this technique in the context of IcedID infections leading to XingLocker ransomware deployment.

## Attack Chain

1. Initial access is gained through an initial vector (e.g., phishing).
2. The attacker obtains elevated privileges on the system.
3. The attacker identifies the registry keys corresponding to Windows Defender services such as `WdBoot`, `WdFilter`, `WdNisDrv`, `WdNisSvc`, `WinDefend`, and `SecurityHealthService`.
4. The attacker uses a tool like `reg.exe` or PowerShell to modify the `Start` value within these registry keys to `0x00000004`. For example, `reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 4 /f`
5. The system's security services are disabled, preventing real-time threat detection and response.
6. The attacker deploys and executes malware, such as IcedID or other payloads, without interference from Windows Defender.
7. The attacker establishes persistence mechanisms to maintain access to the compromised system.
8. Finally, the attacker may proceed to lateral movement, data exfiltration, or ransomware deployment.

## Impact

Disabling Windows Defender services allows attackers to operate undetected on compromised systems, leading to potential data breaches, malware infections, and ransomware deployment. The DFIR Report details how IcedID malware employs this technique to facilitate XingLocker ransomware attacks. Successful execution results in complete loss of endpoint protection, increasing the risk of widespread infection and data compromise across the network.

## Recommendation

*   Enable Sysmon Event ID 13 (Registry Event) logging to monitor registry modifications (data_source).
*   Deploy the Sigma rule "Detect Disabling of Windows Defender Services via Registry Modification" to your SIEM and tune for your environment.
*   Investigate any alerts triggered by registry modifications to Defender service keys with a value of `0x00000004` to identify potentially compromised systems.
*   Correlate registry modification events with process creation events to identify the source of the malicious activity.
*   Monitor for processes accessing or modifying registry keys related to Windows Defender services (affected_products).
