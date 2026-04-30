---
title: Logon Script Registry Modification for Persistence and Privilege Escalation
slug: 2024-01-03-logon-script-registry-modification
description: This brief details the detection of UserInitMprLogonScript registry entry modifications, a technique employed by threat actors for persistence and privilege escalation by ensuring payloads execute automatically at system startup.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
references:
  - https://attack.mitre.org/techniques/T1037/001/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/logon_script_event_trigger_execution.yml
rules:
  - title: Logon Script Registry Modification
    description: Detects modification of the UserInitMprLogonScript registry entry.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1037.001
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Executable Set as Logon Script
    description: Detects an executable being set as the logon script via registry modification.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1037.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This brief focuses on the malicious modification of the `UserInitMprLogonScript` registry entry, a tactic frequently employed by attackers to achieve persistence and escalate privileges on compromised systems. This technique involves altering the registry to ensure that malicious payloads are automatically executed each time the system boots, enabling attackers to maintain persistent access and potentially gain elevated privileges. The original Splunk analytic was published on 2026-04-29 and leverages the Endpoint.Registry data model, making it crucial to have adequate data ingestion from systems monitoring registry events. This technique is attractive to both APT groups and malware operators because it provides a reliable mechanism to automatically execute code within a targeted environment.

## Attack Chain

1.  An attacker gains initial access to the system through methods such as exploiting vulnerabilities or using compromised credentials.
2.  The attacker elevates privileges to gain sufficient access to modify the registry.
3.  The attacker modifies the `UserInitMprLogonScript` registry key under `HKCU` or `HKLM`.
4.  The `registry_value_data` is changed to point to a malicious script or executable.
5.  The system is rebooted, or a user logs in.
6.  The operating system executes the script or executable specified in the modified `UserInitMprLogonScript` registry entry.
7.  The malicious payload executes, allowing the attacker to establish persistence, install malware, or perform other malicious actions.

## Impact

Successful exploitation allows attackers to establish persistent access to the compromised system. This can lead to data exfiltration, further compromise of the network, or the deployment of ransomware. The modification of the `UserInitMprLogonScript` registry entry can be used to execute malicious code every time a user logs in, making it difficult to eradicate the attacker's presence without proper detection and remediation. This technique enables adversaries to maintain long-term control over the affected system.

## Recommendation

*   Enable Sysmon EventID 13 (registry events) with appropriate filtering to monitor changes to the `UserInitMprLogonScript` registry key (data_source).
*   Deploy the Sigma rule `Logon Script Registry Modification` to your SIEM and tune for your environment.
*   Investigate any modifications to the `UserInitMprLogonScript` registry key for unexpected executables or scripts.
*   Correlate suspicious registry modifications with other endpoint activity, such as network connections or process creation, to identify potential malicious behavior.
