---
title: Persistence via Hidden Run Key Detected
slug: 2026-05-persistence-hidden-run-key
description: This rule detects a persistence mechanism that utilizes the NtSetValueKey native API to create a hidden (null terminated) registry key, evading detection from system utilities.
date: "2026-05-12T18:40:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - registry
  - windows
vendors:
  - Elastic
  - Crowdstrike
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - Sysmon Registry Events
  - SentinelOne Cloud Funnel
  - CrowdStrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/outflanknl/SharpHide
  - https://github.com/ewhitehats/InvisiblePersistence/blob/master/InvisibleRegValues_Whitepaper.pdf
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_via_hidden_run_key_valuename.toml
rules:
  - title: Detect Hidden Run Key Value Name via NtSetValueKey
    description: Detects the creation of hidden (null terminated) registry values under the Run key path, indicating a persistence mechanism.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Process Creation from Hidden Run Key Payload
    description: Detects process creation events where the command line matches a known payload from a hidden Run key value, indicating the execution of malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.003
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies a persistence mechanism on Windows systems where attackers use the `NtSetValueKey` native API to create hidden registry keys, specifically within the Run key paths. This technique allows the execution of malicious code upon system startup or user logon while remaining concealed from typical system utilities like Registry Editor (regedit). The rule focuses on detecting changes to specific registry keys under the `Run` key path, including `CurrentVersion\\Run`, `WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run`, and `Policies\\Explorer\\Run`. This technique is used to establish persistence and evade detection, allowing malicious code to execute without the user's knowledge or consent.

## Attack Chain

1.  Attacker gains initial access to the system.
2.  Attacker uses a tool like `SharpHide` or custom code to interact with the `NtSetValueKey` API.
3.  The attacker creates a new registry value under one of the `Run` key paths.
4.  The registry value name is crafted with a null terminator, hiding it from standard registry enumeration tools.
5.  The registry value data contains a command to execute a malicious payload.
6.  The system restarts or the user logs on.
7.  The operating system reads the `Run` keys and executes the hidden command.
8.  The malicious payload is executed, establishing persistence and potentially leading to further compromise.

## Impact

Successful exploitation allows attackers to maintain persistent access to compromised systems, enabling them to execute malicious code, steal sensitive information, or perform other unauthorized actions. This technique bypasses standard defenses, making it difficult for administrators to detect and remove the malicious persistence mechanism. The impact includes potential data breaches, system compromise, and long-term unauthorized access.

## Recommendation

*   Enable Sysmon registry event logging to detect the use of `NtSetValueKey` for hidden registry key creation.
*   Deploy the Sigma rule "Detect Hidden Run Key Value Name via NtSetValueKey" to detect the creation of hidden registry values under the `Run` key path in the Windows registry.
*   Investigate any registry events that modify the `Run` keys and involve null-terminated value names, as these may indicate malicious activity.
*   Use the investigation steps from the original rule to triage and analyze possible malicious findings.
*   Monitor process executions originating from the `Run` keys, looking for suspicious command lines or unexpected processes.
