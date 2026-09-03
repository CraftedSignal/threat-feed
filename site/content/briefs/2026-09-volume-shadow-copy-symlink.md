---
title: Credential Access via Volume Shadow Copy Symlink Creation
slug: 2026-09-volume-shadow-copy-symlink
description: Adversaries utilize the Windows mklink utility to create symbolic links to Volume Shadow Copies, enabling unauthorized access to sensitive files like the SAM database for credential theft.
date: "2026-09-03T12:37:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - living-off-the-land
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Shadow Copies storage symbolic link creation using operating systems utilities.
    confidence_band: high
rules:
  - title: Detect Volume Shadow Copy Symlink Creation Via Mklink
    description: Detects the use of the mklink utility to create symbolic links to Volume Shadow Copies, a common technique for credential harvesting.
    platform: sigma
    severity: high
    tactics:
      - credential_access
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
    - action: Deploy the provided Sigma rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in source
  hunt_leads:
    - lead: Search for historical process creation logs containing mklink and HarddiskVolumeShadowCopy strings.
      technique_id: T1003
      data_needed:
        - CommandLine
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this as a technique for credential dumping.
---

Adversaries frequently target the Windows Volume Shadow Copy Service (VSS) to bypass file access controls and extract sensitive system files, including the Security Account Manager (SAM), SYSTEM, and SECURITY hives. By using the built-in `mklink` command, an attacker can create a symbolic link to a shadow copy volume, essentially mounting the protected data to a location where it can be read or copied directly. This technique allows for credential dumping while avoiding traditional file locking mechanisms that would typically prevent direct access to these files while the operating system is running. Defenders should monitor for the creation of symbolic links specifically targeting HarddiskVolumeShadowCopy paths, as this is a high-fidelity indicator of credential harvesting attempts rather than standard system administration or backup activity.

## Attack Chain

1. Attacker gains initial access and executes a command shell with administrative privileges.
2. Attacker checks for existing shadow copies using `vssadmin list shadows`.
3. Attacker creates a new shadow copy of the system drive using `vssadmin create shadow /for=C:`.
4. Attacker identifies the unique shadow copy device path from the output.
5. Attacker executes `mklink /d` to map the shadow copy path to a local directory (e.g., `C:\shadowcopy`).
6. Attacker navigates to the linked directory to access `C:\shadowcopy\Windows\System32\config\SAM`.
7. Attacker copies the target credential hive files to an attacker-controlled directory.
8. Attacker exfiltrates the hives or executes a tool like Mimikatz locally to extract hashes.

## Impact

Successful execution of this technique provides attackers with full access to the SAM database, allowing them to perform offline password cracking or Pass-the-Hash attacks. This often leads to lateral movement, privilege escalation, and full domain compromise. In enterprise environments, this represents a critical breach of credential confidentiality, allowing attackers to persist with high-level access even after the initial intrusion vector is remediated.

## Recommendation

- Deploy the Sigma rule below to detect unauthorized usage of `mklink` targeting volume shadow copies.
- Enable Sysmon or Windows Event Log (ID 4688) process creation logging with command line arguments.
- Implement monitoring for excessive or suspicious usage of `vssadmin` or `wmic` commands to manage shadow copies.
- Restrict administrative privileges to prevent non-authorized users from executing VSS management commands.
- Audit administrative PowerShell and CMD sessions for the presence of mklink command patterns.
