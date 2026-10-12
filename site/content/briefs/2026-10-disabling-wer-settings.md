---
title: Modification of Windows Registry to Disable Windows Error Reporting
slug: 2026-10-disabling-wer-settings
description: Adversaries modify Windows Registry keys to disable Windows Error Reporting (WER) to suppress diagnostic notifications, thereby concealing malicious activity and reducing the likelihood of detection.
date: "2026-10-12T18:11:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry
  - windows
  - persistence
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The analytic detects modifications in the Windows registry to disable Windows Error Reporting (WER) settings.
    confidence_band: high
rules:
  - title: Detect Modification of Windows Error Reporting Registry Key
    description: Detects the modification of Windows Registry keys to disable Windows Error Reporting, often used by malware to suppress crash alerts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy registry monitoring for WER settings
      owner: Detection Engineering
      due: 72h
      evidence: Source analytic description.
  hunt_leads:
    - lead: Registry modifications targeting WER paths
      technique_id: T1112
      data_needed:
        - Sysmon Event ID 13
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source explicitly identifies registry monitoring as the primary detection method.
  mitigation_plan:
    - priority: medium
      action: Implement GPO to restrict registry access
      owner: IT Operations
      addresses: T1112
      evidence: Preventing unauthorized registry modification mitigates persistence and evasion techniques.
---

Adversaries often target Windows Error Reporting (WER) settings to evade detection by suppressing error notifications triggered by malicious processes or unstable payloads. By modifying registry keys to disable WER, threat actors ensure that crashes caused by their tools - such as infostealers like Azorult - do not generate alerts that would be visible to system administrators or security software. This technique, classified under subversion of defensive features, is commonly observed in malware campaigns where long-term persistence and stealth are required. Defending against this requires monitoring specific registry paths under 'SOFTWARE\Microsoft\Windows\Windows Error Reporting' for modifications that set the 'Disabled' flag to '0x00000001'. While legitimate administrative changes to WER are possible, they are uncommon in standard user environments, making this behavior a high-fidelity indicator of potential adversarial activity.

## Attack Chain

1. Attacker gains initial access to the target endpoint via social engineering or exploitation of a vulnerability.
2. Attacker executes malicious code (e.g., a malware payload) to establish an initial foothold.
3. Malware executes a registry modification command (e.g., 'reg add') to interact with the system hive.
4. The process modifies 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Disabled' or related registry paths.
5. The registry value is set to '0x00000001', effectively disabling the WER service for subsequent operations.
6. Malware performs follow-on activities, such as credential theft or exfiltration, while remaining silent in the event of local crashes.

## Impact

Successful exploitation allows attackers to operate with a reduced footprint, evading detection mechanisms that monitor for abnormal application crashes. This activity is frequently linked to malware such as Azorult, which leverages this suppression to prevent forensic artifacts from being generated after execution errors, potentially leading to widespread information theft and persistent unauthorized access across impacted organizational networks.

## Recommendation

* Deploy detection logic to monitor for registry modifications within 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\' where the value is set to '0x00000001'.
* Enable Sysmon Event ID 13 (RegistryEvent) to capture these modifications, as it provides the necessary visibility into the process path, user context, and registry keys modified.
* Use the provided Sigma rule in the SIEM to flag potential defense evasion behavior, tuning out known administrative service account activity.
* Audit endpoint configuration policies to ensure that registry modifications to critical system reporting features are restricted to authorized administrators.
