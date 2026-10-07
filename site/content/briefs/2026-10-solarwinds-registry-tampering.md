---
title: SolarWinds Processes Modifying Registry to Disable Services
slug: 2026-10-solarwinds-registry-tampering
description: Adversaries may abuse compromised or legitimate SolarWinds binaries to disable security services by modifying Windows Registry 'Start' values, a technique used for defense evasion.
date: "2026-10-07T16:41:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - supply-chain
  - windows
  - registry
vendors:
  - SolarWinds
products:
  - Orion Platform
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An adversary may abuse this technique to manipulate relevant security services.
    confidence_band: high
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_solarwinds_backdoor_service_disabled_via_registry.toml
rules:
  - title: Detect SolarWinds Process Disabling Services via Registry
    description: Detects when known SolarWinds binaries modify a service Start registry key to 4 (Disabled), which is a common defense evasion technique.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the registry-based detection rule to identify service tampering
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID b9960fef-82c6-4816-befa-44745030e917
  hunt_leads:
    - lead: Search for instances where SolarWinds binaries have modified registry keys ending in \Start
      technique_id: T1562.001
      data_needed:
        - Registry Event Logs (Sysmon 12/13)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source rule logic
  mitigation_plan:
    - priority: short_term
      action: Restrict registry write permissions for service configuration keys for service accounts running SolarWinds
      owner: IT Operations
      addresses: T1562.001
      evidence: Response and remediation guide
---

Adversaries targeting environments using SolarWinds software may leverage the high-level system permissions granted to these processes to perform defense evasion. By modifying specific Windows Registry keys that control service initialization, attackers can effectively disable security tools or critical system defenses. This behavior, often associated with supply chain compromises such as the Sunburst backdoor, involves SolarWinds binaries altering the 'Start' value of services to '4', which signifies that the service is disabled. Defenders should monitor for registry modifications originating from specific SolarWinds process names that correspond to standard system management tasks but result in the neutralization of security software. Given the broad deployment and deep system access typically required by SolarWinds, identifying unauthorized configuration changes at the registry level is a critical component of maintaining endpoint integrity.

## Impact

Successful exploitation allows an adversary to neutralize security software and other critical services on a compromised host, facilitating undetected lateral movement and persistent presence. This technique has been historically associated with advanced persistent threat actors capable of executing complex supply chain compromises. Unauthorized service disabling can severely degrade the visibility of security teams, leading to potential data exfiltration or system-wide disruption within the target organization.

## Recommendation

Detection engineering teams should implement monitoring for registry write events initiated by authorized SolarWinds processes where the target value is set to disabled.
- Deploy the provided Sigma rule to monitor for registry modifications to service 'Start' keys.
- Correlate registry modification events with process creation logs to verify the identity of the modifying process.
- Establish a baseline for authorized configuration changes during scheduled maintenance windows to reduce false-positive alerts.
- Review and restrict service-level permissions for SolarWinds processes to ensure they adhere to the principle of least privilege.
