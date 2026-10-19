---
title: Detection of Password Manager and Credential Discovery Activity
slug: 2026-10-windows-password-discovery
description: Adversaries utilize command-line utilities like 'dir' and 'findstr' to locate password manager databases and sensitive credential files to facilitate credential theft and privilege escalation.
date: "2026-10-19T02:52:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - discovery
  - credential-access
  - post-exploitation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: The following analytic identifies command-line activity that searches for files related to password manager software, such as *.kdbx* and *credential*.
    confidence_band: high
rules:
  - title: Detect Password Manager and Credential File Discovery
    description: Detects the use of 'dir' or 'findstr' to search for password manager databases, credential files, and sensitive system artifacts
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1555.005
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
    - action: Deploy Sigma rule to monitor for credential discovery patterns
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command patterns used by adversaries for discovery.
  hunt_leads:
    - lead: Search for historical process execution logs matching common password manager file patterns
      technique_id: T1555.005
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies this as a post-exploitation discovery technique used by multiple threat actors.
---

This threat brief focuses on common adversary behavior involving the discovery of sensitive local files, specifically password manager databases and credential stores. Attackers leverage native Windows command-line utilities, including 'dir' and 'findstr', to scan filesystems for artifacts such as '*.kdbx*', '*credential*', and 'Ntds.dit'. This discovery phase is a precursor to post-exploitation activities, including credential harvesting, lateral movement, and data exfiltration. Observed in campaigns associated with Prestige Ransomware, Scattered Spider, and various stealer malware, this activity highlights the necessity of monitoring command-line process telemetry for reconnaissance patterns. By identifying these searches in real-time, security operations teams can detect unauthorized attempts to map the local attack surface before secrets are accessed or extracted.

## Impact

Successful execution of these discovery commands enables attackers to identify the location of high-value targets, such as password vaults and active directory databases. If the attacker subsequently exfiltrates these files or extracts credentials, it can result in full account compromise, domain-wide privilege escalation, and massive data breaches within the targeted organization.

## Recommendation

- Deploy the provided Sigma rule to monitor for process executions involving common reconnaissance patterns against sensitive file extensions.
- Enable Sysmon (Event ID 1) or Windows Security Event Logs (Event ID 4688) to capture detailed command-line arguments for all process executions.
- Establish alerting thresholds for 'dir' or 'findstr' commands when the arguments target known sensitive file types.
- Review and tune the detection logic to account for legitimate system administration scripts that may query similar paths.
