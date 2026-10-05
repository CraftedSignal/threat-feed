---
title: Windows Registry Run Key Persistence Monitoring
slug: 2026-10-windows-run-key-persistence
description: Detection of unauthorized modifications to Windows registry autostart keys, a common technique used by threat actors to maintain persistence across system reboots.
date: "2026-10-05T17:57:55Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - windows
  - registry
  - detection
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: In order to survive reboots and other system interrupts, attackers will modify run keys within the registry or leverage startup folder items as a form of persistence.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries may achieve persistence by referencing a program with a registry run key.
    confidence_band: high
rules:
  - title: Detect Suspicious Registry Run Key Modification
    description: Detects modifications to Windows registry Run and RunOnce keys, often used for persistence.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy registry monitoring rules for common autostart locations
      owner: Detection Engineering
      due: 72h
      evidence: Source rule provides specific paths for monitoring
  hunt_leads:
    - lead: Search for unsigned executables referenced in Registry Run keys
      technique_id: T1547.001
      data_needed:
        - Registry set events with process context
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Osquery transformation logic in source
---

Adversaries frequently achieve persistence on compromised Windows systems by modifying registry run keys to ensure their malicious code executes automatically upon user login or system startup. This technique, classified under MITRE ATT&CK as T1547.001, allows malware to re-establish access under the context of the affected user account. This brief focuses on detecting these modifications by monitoring specific, highly-abused registry paths including HKLM and HKEY_USERS run keys. While legitimate software installations, system updates, and administrative activities often modify these keys, unauthorized changes by non-standard processes are strong indicators of potential compromise. Defenders should establish a baseline of common installers and administrative tools to reduce noise while focusing on registry changes originating from unexpected processes or unsigned executables.

## Impact

Successful exploitation allows attackers to maintain long-term access to compromised hosts, bypass traditional security controls that trigger only on initial execution, and execute secondary payloads in the context of user sessions. This persistence is a critical stage in the attack lifecycle for ransomware operations, data exfiltration, and long-term espionage campaigns.

## Recommendation

1. Deploy the provided Sigma rule to monitor registry modification events, focusing on the specific Run and RunOnce keys enumerated in the rule logic.
2. Implement registry auditing (specifically process-level creation and modification events) to capture the parent process context for each modification.
3. Integrate Osquery to perform ad-hoc hunting for unsigned services or suspicious persistence entries on hosts where a registry modification alert has fired.
4. Perform baseline analysis to tune out legitimate installers (e.g., C:\Program Files, msiexec.exe) from the alerting path.
