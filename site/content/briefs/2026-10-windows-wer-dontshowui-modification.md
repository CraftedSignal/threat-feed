---
title: Modification of Windows Error Reporting Registry Key by DarkGate Malware
slug: 2026-10-windows-wer-dontshowui-modification
description: The DarkGate malware modifies the Windows Error Reporting 'DontShowUI' registry key to 0x00000001, suppressing error dialogs to remain stealthy during malicious installation.
date: "2026-10-12T18:12:19Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - DarkGate
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
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
    evidence: The analytic detects modifications to the Windows Error Reporting registry key DontShowUI to suppress error reporting dialogs.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml#L1020
rules:
  - title: Detect Windows Error Reporting DontShowUI Registry Modification
    description: Detects modifications to the Windows Error Reporting DontShowUI registry value, a technique used by DarkGate to suppress error notifications.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry path and value.
  enrichment_needed:
    - item: DarkGate malware samples
      owner: CTI
      reason: Gather more indicators of attack for correlation.
      evidence: Malpedia reference.
  hunt_leads:
    - lead: Search for existing registry modifications to DontShowUI in historical logs.
      technique_id: T1112
      data_needed:
        - Registry change logs (Sysmon ID 13)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Associated with DarkGate malware activity.
  mitigation_plan:
    - priority: short_term
      action: Review Group Policy settings for Windows Error Reporting to ensure standard posture.
      owner: IT Operations
      addresses: T1112
      evidence: Malicious modification of WER settings.
  gaps:
    - Lack of host-based process lineage enrichment in the source.
---

DarkGate malware, identified in multiple campaigns, performs modifications to the Windows Error Reporting (WER) registry configuration as a defensive evasion tactic. Specifically, it targets the 'DontShowUI' registry value within the 'SOFTWARE\Microsoft\Windows\Windows Error Reporting' path, setting the value to '0x00000001'. By performing this modification, the malware suppresses Windows error reporting dialogs that would typically trigger if a process crashes during the execution of malicious payloads. This behavior is a key indicator of stealth-oriented malware installation, as it prevents alerting the user or system administrators to abnormal application behavior during the initial deployment phase. Defenders should monitor for registry modifications to this path to identify processes attempting to evade standard OS-level error notifications.

## Attack Chain

1. Initial delivery or execution of the DarkGate malware binary.
2. Malware checks environment for specific security software or sandbox artifacts.
3. Malware initiates persistence and installation routines on the victim host.
4. Malware accesses the registry path 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting'.
5. Malware performs a write operation to set the 'DontShowUI' value to '0x00000001'.
6. Malware proceeds with main malicious payload execution, such as C2 communication or data exfiltration.
7. If a crash occurs during execution, the OS suppresses the error notification, preventing user discovery.

## Impact

The suppression of WER dialogs allows the DarkGate malware to operate without generating user-visible alerts, which increases the likelihood of a successful, undetected installation. This technique is designed to bypass basic user awareness and diagnostic telemetry that might otherwise highlight the presence of malicious software during its setup phase. Failure to detect this activity leaves the environment susceptible to the full functionality of the DarkGate payload, which includes remote access capabilities and credential theft.

## Recommendation

1. Deploy the provided Sigma rule to detect unauthorized modifications to the 'DontShowUI' registry value via Sysmon Event ID 13.
2. Implement monitoring for 'SetRegistryValue' actions targeting the 'Windows Error Reporting' hive.
3. Validate internal configurations to ensure that registry monitoring covers the HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting path.
4. Use the risk-based alerting framework to aggregate instances of this registry modification with other suspicious behaviors associated with DarkGate.
