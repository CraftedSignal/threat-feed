---
title: Suspicious Modifications to Windows Security Support Provider (SSP) Registry
slug: 2024-01-ssp-registry-modification
description: Adversaries may modify the Windows Security Support Provider (SSP) configuration in the registry to establish persistence or evade defenses.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-evasion
  - registry-modification
  - ssp
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - CrowdStrike FDR
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_via_lsa_security_support_provider_registry.toml
rules:
  - title: Suspicious SSP Registry Modification
    description: Detects registry modifications related to the Windows Security Support Provider (SSP) configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.005
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Process Modifying SSP Registry
    description: Detects processes other than msiexec.exe modifying the Security Packages registry keys.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1547.005
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers can abuse the Windows Security Support Provider (SSP) mechanism to establish persistence on a compromised system. SSPs are DLLs loaded into the Local Security Authority Subsystem Service (LSASS) process, which handles authentication in Windows. By modifying specific registry keys related to SSP configuration, attackers can force LSASS to load malicious DLLs at startup, effectively creating a persistent backdoor. This technique is often used to maintain unauthorized access to a system even after a reboot. The registry keys of interest are `HKLM\SYSTEM\*\ControlSet*\Control\Lsa\Security Packages` and `HKLM\SYSTEM\*\ControlSet*\Control\Lsa\OSConfig\Security Packages`. Successful exploitation allows the attacker to intercept and manipulate authentication credentials.

## Attack Chain

1. An attacker gains initial access to a Windows system through an exploit or compromised credentials (not detailed in source).
2. The attacker escalates privileges to gain administrative rights on the system.
3. The attacker modifies the registry key `HKLM\SYSTEM\*\ControlSet*\Control\Lsa\Security Packages` to include a path to a malicious DLL.
4. Alternatively, the attacker modifies the registry key `HKLM\SYSTEM\*\ControlSet*\Control\Lsa\OSConfig\Security Packages` to include a path to a malicious DLL.
5. The attacker triggers a system reboot, or restarts the LSASS process, causing the malicious SSP DLL to be loaded.
6. The malicious DLL intercepts authentication credentials and exfiltrates them or performs other malicious actions.
7. The attacker maintains persistent access to the system, even after reboots.

## Impact

Successful exploitation allows attackers to achieve persistence and potentially compromise sensitive credentials handled by LSASS. This can lead to lateral movement within the network, data exfiltration, and further system compromise. The impact is significant as it bypasses standard security measures and provides a persistent foothold for malicious activities.

## Recommendation

*   Deploy the Sigma rule "Suspicious SSP Registry Modification" to your SIEM to detect unauthorized modifications to SSP registry keys.
*   Enable Sysmon registry event logging to provide the necessary data for the Sigma rule to function.
*   Continuously monitor for unexpected processes writing to the `HKLM\SYSTEM\*\ControlSet*\Control\Lsa\Security Packages` and `HKLM\SYSTEM\*\ControlSet*\Control\Lsa\OSConfig\Security Packages` registry keys.
*   Review and whitelist legitimate software installers that frequently modify these registry entries to reduce false positives as mentioned in the brief.
*   Ensure access controls and permissions are strictly enforced to limit unauthorized modification of critical registry paths related to Security Support Providers.
