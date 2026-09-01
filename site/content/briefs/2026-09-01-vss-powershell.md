---
title: Credential Access via Volume Shadow Copy Creation
slug: 2026-09-01-vss-powershell
description: Adversaries can utilize PowerShell to programmatically create Volume Shadow Copies, enabling the offline extraction of sensitive files like the Active Directory ntds.dit database.
date: "2026-09-01T11:05:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - powershell
  - wmi
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information
    confidence_band: high
rules:
  - title: Detect VSS Creation via PowerShell
    description: Detects the creation of Volume Shadow Copies using PowerShell WMI method calls, often used to access locked files like ntds.dit
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: High confidence in identifying unauthorized credential access attempts via VSS
  hunt_leads:
    - lead: Search for Event ID 4104 containing 'Win32_ShadowCopy' over the last 30 days
      technique_id: T1003.003
      data_needed:
        - Powershell Script Block logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This technique is a common method for exfiltrating the NTDS database.
  mitigation_plan:
    - priority: short_term
      action: Review and restrict administrative privileges for PowerShell execution
      owner: IT Operations
      addresses: Unauthorized credential access
      evidence: Restricting execution reduces the impact of compromised accounts.
---

Adversaries often attempt to bypass file system locks to access sensitive system files that are otherwise protected by the Windows operating system. By programmatically creating a Volume Shadow Copy (VSS) via PowerShell using the Win32_ShadowCopy WMI class, an attacker can create a point-in-time snapshot of the volume. This snapshot provides access to a consistent, offline copy of files such as the Active Directory database (ntds.dit) and security hive (SAM), which contain credentials. This technique is a frequent component of post-exploitation phases aimed at credential harvesting and offline cracking. Defenders must monitor PowerShell Script Block logs for the specific WMI class method calls associated with VSS creation to detect unauthorized snapshots of system volumes.

## Attack Chain

1. Attacker establishes interactive shell access to a Windows host.
2. Attacker enumerates system volumes to identify the drive containing the NTDS database.
3. Attacker executes a PowerShell script to invoke the Win32_ShadowCopy WMI class.
4. Script execution triggers the Create method on the Win32_ShadowCopy class with ClientAccessible parameters.
5. The Windows VSS service generates a shadow copy of the specified volume.
6. Attacker maps the shadow copy using 'mklink' or 'vssadmin' to expose the file contents.
7. Attacker copies the sensitive ntds.dit file from the shadow copy location to a staging folder.
8. Attacker exfiltrates the database for offline credential recovery.

## Impact

Successful execution of this technique allows unauthorized access to domain credentials, potentially leading to full domain compromise, lateral movement, and persistent access to the enterprise environment.

## Recommendation

Deploy the provided Sigma rule to detect suspicious PowerShell script blocks invoking the Win32_ShadowCopy WMI class. Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to ensure visibility into the script execution. Regularly audit and limit the use of administrative PowerShell privileges to authorized service accounts and administrators.
