---
title: Detecting Malicious Windows Share Manipulation via net.exe
slug: 2026-10-net-exe-shares
description: Attackers utilize the net.exe utility to create or delete Windows shares as a mechanism for lateral movement, data exfiltration, and establishing persistence.
date: "2026-10-12T17:36:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - post-exploitation
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: The following analytic detects the creation or deletion of Windows shares using the net.exe command.
    confidence_band: high
rules:
  - title: Detect Windows Share Creation or Deletion via net.exe
    description: Detects the use of net.exe to create, delete, or modify Windows network shares, a common technique for post-exploitation staging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for net.exe share manipulation.
  hunt_leads:
    - lead: Search for net.exe execution with share parameters over the last 30 days.
      technique_id: T1070.005
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Technique is a common post-exploitation step.
  mitigation_plan:
    - priority: medium_term
      action: Restrict command-line access for non-privileged accounts
      owner: IT Operations
      addresses: T1070.005
      evidence: Limiting utility access reduces attack surface.
---

Attackers frequently leverage the native Windows utility `net.exe` to manipulate network shares as part of post-exploitation activities. This technique allows adversaries to create shares for staging sensitive data prior to exfiltration, or to delete existing shares to hinder forensic analysis or disrupt system operations. This activity has been observed in association with various malware families and campaigns, including Hidden Cobra, Prestige Ransomware, and DarkGate. Defenders must distinguish this malicious use of `net.exe` from legitimate administrative actions performed by system administrators or automated scripts. Effective detection requires visibility into granular process telemetry, specifically capturing the full command-line arguments and parent process context associated with `net.exe`.

## Attack Chain

1. Initial access is established through phishing or exploitation of a network-facing service.
2. The attacker executes a discovery command to identify existing network resources and file shares.
3. The adversary identifies a target directory or system for staging data or malware.
4. The attacker executes `net.exe share <name>=<path>` to create a new, potentially hidden or unauthorized network share.
5. Sensitive files are moved or copied into the newly created share for centralized access or exfiltration.
6. The attacker uses `net.exe share <name> /delete` to remove the share after the data has been exfiltrated to minimize the forensic footprint.
7. Final objectives, such as data exfiltration or the propagation of ransomware, are completed.

## Impact

Unauthorized modification of network shares can facilitate large-scale data exfiltration, enable the rapid spread of malware across an enterprise network, or result in significant service disruption. Persistent shares created by attackers can also serve as long-term backdoors for re-entry into the environment.

## Recommendation

1. Deploy the provided Sigma rule to monitor `net.exe` command-line arguments indicative of share manipulation.
2. Baseline administrative activity in your environment to distinguish legitimate share management from potential adversary behavior.
3. Enable Sysmon or equivalent EDR process-creation logging to ensure the full `CommandLine` field is captured for analysis.
4. Integrate the identified `net.exe` patterns with risk-based alerting in your SIEM to correlate this activity with other suspicious behaviors like credential dumping or lateral movement.
