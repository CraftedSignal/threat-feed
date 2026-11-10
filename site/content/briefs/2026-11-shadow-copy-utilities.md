---
brief_id: brief-2026-11-10-shadow-copy-utilities
event_id: brief-2026-11-10-shadow-copy-utilities
revision: 1
activity_at: "2026-11-10T03:07:19Z"
title: Shadow Copies creation via native OS utilities
slug: 2026-11-shadow-copy-utilities
description: Adversaries may use native Windows utilities like vssadmin, wmic, or PowerShell to create shadow copies to facilitate credential access through offline extraction of the ntds.dit file.
date: "2026-11-10T03:07:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - credential-access
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    subtechnique_id: T1003.002
    subtechnique_name: Security Account Manager
    evidence: Shadow Copies creation using operating systems utilities, possible credential access
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    subtechnique_id: T1003.003
    subtechnique_name: NTDS
    evidence: Shadow Copies creation using operating systems utilities, possible credential access
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_creation.yml
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://www.levelblue.com/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntds.dit-system/
rules:
  - title: Detect Shadow Copies Creation via OS Utilities
    description: Detects the execution of PowerShell, wmic, or vssadmin with command line arguments indicative of shadow copy creation
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1003.002
      - T1003.003
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
    - action: Deploy the provided Sigma rule to SIEM environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for shadow copy creation
  hunt_leads:
    - lead: Identify past executions of vssadmin or wmic involving shadow copies
      technique_id: T1003.003
      data_needed:
        - Process creation logs (Event ID 1)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Shadow copy creation is a common precursor to credential dumping
---

Threat actors frequently leverage built-in Windows utilities to create Volume Shadow Copies. This technique is a precursor to credential dumping, as it allows attackers to obtain copies of the Active Directory database (ntds.dit) and the SYSTEM registry hive, which are normally locked by the operating system.

## Impact

Successful exploitation allows an adversary to gain offline access to the Active Directory database, leading to the potential compromise of domain-wide credentials and escalation of privileges.

## Recommendation

- Deploy the provided Sigma rule to detect the execution of utilities known for manipulating shadow copies.
- Establish a baseline for administrative backup activities to differentiate legitimate system administration from malicious activity.
- Restrict access to administrative tools and sensitive system files to only authorized service accounts.
