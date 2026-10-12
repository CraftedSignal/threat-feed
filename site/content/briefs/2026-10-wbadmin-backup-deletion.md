---
title: Detection of Ransomware Backup Deletion via WBAdmin
slug: 2026-10-wbadmin-backup-deletion
description: Attackers utilize the native Windows utility wbadmin.exe to delete system backups and catalogs as part of ransomware operations to impede victim recovery.
date: "2026-10-12T18:00:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - impact
  - windows
  - wbadmin
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: The following analytic detects the execution of wbadmin.exe with flags that delete backup files, specifically targeting catalog or system state backups.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1490/
  - https://thedfirreport.com/2020/10/08/ryuks-return/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md
rules:
  - title: Detect WBAdmin Backup Deletion
    description: Detects the execution of wbadmin.exe with command-line arguments intended to delete system backups or catalogs.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for wbadmin deletion
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific command line patterns for detection
  hunt_leads:
    - lead: Search historical logs for wbadmin.exe with delete flags
      technique_id: T1490
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Ransomware operators frequently use this to destroy local recovery options
---

This detection focuses on the malicious use of the Windows Backup utility (wbadmin.exe) to purge system state backups and backup catalogs. This technique is a well-documented stage in the ransomware attack chain, specifically observed in campaigns by actors deploying Ryuk, Prestige, and Chaos ransomware. By deleting backups, attackers ensure that victims cannot easily restore encrypted data, thereby increasing the pressure to pay ransom. While wbadmin is a legitimate administrative tool, its use with specific deletion arguments in a production environment is highly anomalous and indicates a deliberate attempt to sabotage recovery capabilities. Security teams should prioritize visibility into process-level telemetry to identify unauthorized calls to this binary.

## Attack Chain

1. Attacker gains initial access to the target environment (e.g., via phishing or exploit).
2. Attacker performs credential harvesting to obtain local administrator or SYSTEM privileges.
3. Attacker identifies backup repositories and system state configurations on the target host.
4. Attacker executes `wbadmin.exe` with `delete` parameters to remove existing backup catalogs.
5. Attacker executes `wbadmin.exe` with additional flags to purge system state backups.
6. Attacker proceeds to execute ransomware encryption payloads, knowing recovery is hindered.
7. Final objective is achieved: data is encrypted and local restoration options are destroyed.

## Impact

Successful execution of this technique results in the loss of local system recovery options, rendering automated or manual restoration impossible. This leads to extended downtime, significant operational disruption, and increased leverage for ransomware actors. This behavior has been observed across various ransomware-as-a-service (RaaS) models, affecting a broad range of sectors including critical infrastructure, healthcare, and enterprise organizations.

## Recommendation

- Deploy the Sigma rules in this brief to detect the execution of `wbadmin.exe` with deletion arguments.
- Enable command-line logging (Event ID 4688 with command-line auditing enabled) or Sysmon Event ID 1 to ensure full visibility into process arguments.
- Review administrative processes to establish a baseline and tune the detection to ignore authorized maintenance windows.
- Use the process GUID and parent process relationships provided by EDR telemetry to differentiate between legitimate system administration and malicious post-exploitation activity.
