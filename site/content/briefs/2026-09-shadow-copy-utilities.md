---
title: Detection of Shadow Copy Creation via System Utilities
slug: 2026-09-shadow-copy-utilities
description: Adversaries frequently abuse native Windows utilities like vssadmin and wmic to create volume shadow copies, a precursor to offline credential theft via NTDS.dit extraction.
date: "2026-09-01T12:25:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows-security
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Shadow Copies creation using operating systems utilities, possible credential access
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Shadow Copies creation using operating systems utilities, possible credential access
    confidence_band: high
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
  - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/tutorial-for-ntds-goodness-vssadmin-wmis-ntdsdit-system/
rules:
  - title: Detect Suspicious Shadow Copy Creation
    description: Detects the use of system utilities (vssadmin, wmic, powershell) to create volume shadow copies, a common step in credential theft.
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
    - action: Deploy the Sigma rule to monitor for VSS command-line patterns
      owner: Detection Engineering
      due: 48h
      evidence: Source-provided Sigma rule logic
  hunt_leads:
    - lead: Search historical logs for vssadmin, wmic, or powershell usage involving 'shadow' and 'create'
      technique_id: T1003.002
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique commonly used for credential theft
---

Threat actors commonly leverage built-in Windows utilities to interact with the Volume Shadow Copy Service (VSS) for malicious purposes. While VSS is a legitimate administrative feature for backups, attackers use it to create snapshots of the operating system volume. Once a shadow copy is created, the attacker can extract the NTDS.dit file, which contains the Active Directory database and hashed credentials for domain users. By using trusted system binaries (Living off the Land), attackers attempt to bypass detection mechanisms that focus on non-standard tools or malware. This technique is often seen in the post-exploitation phase of a compromise to facilitate lateral movement or privilege escalation. Defensive visibility into the command-line arguments used during VSS operations is critical for identifying unauthorized credential access attempts.

## Impact

Successful exploitation of this technique leads to the acquisition of the NTDS.dit file, enabling attackers to perform offline cracking of domain credentials. This significantly increases the risk of full domain compromise, unauthorized access to sensitive data, and potential persistence in the environment. Targeted sectors include any organization relying on Active Directory, making this a common TTP across various ransomware and espionage campaigns.

## Recommendation

Detection engineering teams should monitor for the execution of VSS-related commands by non-administrative users or processes.
- Implement the provided Sigma rule to alert on suspicious command-line patterns involving vssadmin, wmic, or PowerShell.
- Establish a baseline for legitimate backup administrative activity to reduce noise from backup software or maintenance tasks.
- Ensure Sysmon or equivalent EDR process creation logging is active to capture Image, OriginalFileName, and CommandLine fields.
- Restrict access to administrative tools and sensitive system files to only authorized service accounts.
