---
title: PowerShell SAM Registry Hive Exfiltration
slug: 2026-09-powershell-sam-access
description: Adversaries utilize PowerShell to copy the Security Account Manager (SAM) registry hive from shadow copies for offline credential extraction.
date: "2026-09-03T12:41:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - powershell
  - windows
  - sam-hive
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.002
    technique_name: Security Account Manager
    evidence: Adversaries utilize PowerShell to copy the Security Account Manager (SAM) registry hive from shadow copies for offline credential extraction.
    confidence_band: high
references:
  - https://twitter.com/splinter_code/status/1420546784250769408
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_sam_access.yml
rules:
  - title: Detect Suspicious PowerShell SAM Hive Access
    description: Detects PowerShell scripts accessing SAM hives from shadow copies using common copy cmdlets or .NET methods.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.002
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
    - action: Deploy Sigma rule 1af57a4b to SIEM for monitoring
      owner: Detection Engineering
      due: 24h
      evidence: High confidence in credential theft detection
  hunt_leads:
    - lead: Search for instances of vssadmin.exe creating shadow copies followed by PowerShell file access
      technique_id: T1003.002
      data_needed:
        - Process creation events (4688)
        - Command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documents VSS and PowerShell as the primary vector
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict ACLs on C:\Windows\System32\config\sam
      owner: IT Operations
      addresses: Credential Access TTP
      evidence: Prevents unauthorized read access even with shadow copy bypass
  gaps:
    - Lack of visibility into non-PowerShell file copy utilities
---

Adversaries frequently target the Windows Security Account Manager (SAM) registry hive to harvest local account password hashes. By leveraging Volume Shadow Copies (VSS), attackers bypass file system locks that typically prevent direct access to the SAM database while the operating system is running. PowerShell is commonly used to programmatically locate the path of the SAM file within a mounted shadow copy and execute copy operations to a staging directory. This technique is a critical component of credential access, as it enables offline cracking of NTLM hashes. Defenders should focus on detecting the combined usage of volume shadow copy paths and file-copying cmdlets or .NET file API calls within PowerShell processes, as these actions are rarely performed by legitimate administrative tasks.

## Attack Chain

1. Attacker gains elevated (administrative or SYSTEM) privileges on the target Windows host.
2. Attacker interacts with the Volume Shadow Copy Service (VSS) via 'vssadmin' or WMI to create a snapshot of the C: drive.
3. Attacker identifies the path to the mounted snapshot, typically starting with 'HarddiskVolumeShadowCopy'.
4. Attacker launches a PowerShell process to target the SAM file at '\HarddiskVolumeShadowCopy[N]\Windows\System32\config\sam'.
5. Attacker executes copy commands ('Copy-Item', 'cp', or .NET 'System.IO.File::Copy') to extract the SAM hive to a staging folder (e.g., C:\Windows\Temp).
6. Attacker potentially repeats the process for the SYSTEM and SECURITY hives to facilitate credential decryption.
7. Attacker exfiltrates the hives or decrypts them locally to obtain cleartext credentials or NTLM hashes.

## Impact

Successful exfiltration of the SAM hive allows attackers to perform offline brute-force or dictionary attacks against local account password hashes. If a system contains accounts with cached credentials or local administrative accounts with weak passwords, this technique frequently leads to privilege escalation and horizontal movement across the domain environment.

## Recommendation

Deploy the provided Sigma rule to detect suspicious PowerShell execution patterns involving shadow copy paths. Ensure Sysmon or native Windows Event ID 4688 (Process Creation) with Command Line logging is enabled. Monitor for 'vssadmin.exe' creation followed by PowerShell file access patterns targeting 'sam' or 'system' registry hives. Block or restrict the use of PowerShell for sensitive file system operations in high-security zones where such behavior is non-standard.
