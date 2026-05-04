---
title: Microsoft Office 'Office Test' Registry Persistence Abuse
slug: 2024-01-office-test-registry-persistence
description: Attackers modify the Microsoft Office 'Office Test' Registry key to achieve persistence by specifying a malicious DLL that executes upon application startup.
date: "2024-01-27T17:30:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - registry
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Office
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://unit42.paloaltonetworks.com/unit42-technical-walkthrough-office-test-persistence-method-used-in-recent-sofacy-attacks/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_msoffice_startup_registry.toml
rules:
  - title: Detect Office Test Registry Key Modification
    description: Detects modifications to the Microsoft Office 'Office Test' registry key, which is a common persistence technique.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1137.002
    data_sources:
      - registry_set
      - windows
  - title: Detect DLL Load from Office Test Registry Key
    description: Detects when a DLL specified in the 'Office Test' registry key is loaded by an Office application.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1137.002
    data_sources:
      - image_load
      - windows
rules_count: 2
---

The "Office Test" registry key, located under `HKCU\Software\Microsoft\Office Test\Special\Perf`, is a legitimate feature that allows specifying a DLL to be executed every time an MS Office application is started. Attackers can abuse this functionality by modifying the registry to point to a malicious DLL, achieving persistence on a compromised host. This allows for continued malicious activity even after a system restart or user logout. Elastic has published a rule to detect this behavior. The modification of this registry key, excluding deletions, is a strong indicator of potential abuse, and can be detected via endpoint detection and response (EDR) solutions as well as traditional Sysmon logging.

## Attack Chain

1. An attacker gains initial access to a system, often through phishing or exploiting a vulnerability.
2. The attacker establishes a foothold and escalates privileges to make necessary registry modifications.
3. The attacker modifies the `HKCU\Software\Microsoft\Office Test\Special\Perf` registry key, adding a new entry or modifying an existing one to point to a malicious DLL.
4. The attacker ensures the malicious DLL is present on the system, either by dropping it directly or using existing system tools to download it.
5. A user launches a Microsoft Office application (e.g., Word, Excel, PowerPoint).
6. The Office application loads the DLL specified in the "Office Test" registry key during startup.
7. The malicious DLL executes its payload, which could include establishing a reverse shell, installing malware, or exfiltrating data.
8. The attacker maintains persistence, allowing them to regain access to the system each time an Office application is started.

## Impact

Successful exploitation allows attackers to maintain persistent access to a compromised system. The injected DLL can be used to execute arbitrary code, potentially leading to data theft, malware installation, or further compromise of the network. The relatively low risk score suggests a common technique, but the potential for persistent access makes it a significant threat.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect unauthorized modifications to the "Office Test" registry key (`HKCU\Software\Microsoft\Office Test\Special\Perf\*`).
*   Enable Sysmon Registry event logging to capture registry modifications and activate the Sigma rule above.
*   Monitor process execution logs for Office applications to detect if a suspicious DLL has been loaded or executed, as described in the investigation guide.
*   Implement enhanced monitoring and alerting for similar registry modifications across the network, as described in the remediation steps.
