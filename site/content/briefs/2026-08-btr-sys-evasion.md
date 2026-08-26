---
title: Abuse of Microsoft Defender Boot-Time Removal Driver for Kernel Evasion
slug: 2026-08-btr-sys-evasion
description: Adversaries are weaponizing the legitimate Microsoft Defender Boot-Time Removal (BTR.sys) driver as a kernel primitive to perform arbitrary file and registry modifications during early boot.
date: "2026-08-26T20:17:43Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Microsoft
products:
  - Windows
  - Defender
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Identifies creation of a :changelist NTFS alternate data stream.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: A Windows service Args registry value pointing to a :changelist path.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Adversaries can reproduce this staging outside Defender to abuse BTR.sys.
    confidence_band: high
references:
  - https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/
  - https://github.com/Dump-GUY/BTR_CLI
rules:
  - title: Potential Evasion via Boot Time Removal Tool
    description: Identifies creation of a :changelist NTFS alternate data stream or a Windows service Args registry value pointing to a :changelist path, indicating potential BTR.sys abuse.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1564.004
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
    - action: Deploy Sigma rules for :changelist ADS monitoring.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific logic for ADS and Registry detection.
  hunt_leads:
    - lead: Search for :changelist ADS on system driver files.
      technique_id: T1564.004
      data_needed:
        - File system auditing
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation on BTR.sys abuse.
  mitigation_plan:
    - priority: immediate
      action: Restrict SeLoadDriverPrivilege.
      owner: IT Operations
      addresses: Kernel-mode driver loading abuse.
      evidence: Source suggests monitoring SeLoadDriverPrivilege.
---

Research indicates that the Microsoft Defender Boot-Time Removal driver (BTR.sys) is being abused as a signed kernel-mode primitive for malicious operations. By creating a specific NTFS Alternate Data Stream (ADS) named ':changelist' on a driver file and configuring a service's 'Args' registry value to reference this stream, attackers can instruct BTR.sys to perform file and registry operations with kernel-level privileges. This technique allows adversaries to neutralize security products, modify protected registry keys, and delete files that would otherwise be protected by standard system permissions or other security agents. The abuse relies on the driver's capability to read an RC4-encrypted transaction blob from the ADS during the early boot phase. Because BTR.sys is a legitimately signed Microsoft driver, this method provides a potent vehicle for defense evasion and persistence that operates outside the visibility of typical user-mode security monitoring.

## Attack Chain

1. Attacker drops a malicious or existing system driver file to the filesystem.
2. Attacker creates an NTFS Alternate Data Stream (ADS) named :changelist on the dropped driver file, containing an RC4-encrypted transaction blob.
3. Attacker modifies the registry under HKLM\SYSTEM\CurrentControlSet\Services\&lt;ServiceName> by setting the 'Args' value to point to the created :changelist ADS path.
4. Attacker configures the service 'Group' value to 'Boot Bus Extender' to ensure execution during the early boot sequence.
5. The system performs a reboot, triggering the BTR.sys driver to initialize.
6. The BTR.sys driver reads the encrypted configuration from the :changelist ADS.
7. The driver executes the instructions within the transaction blob, allowing for the deletion of security binaries or modification of registry keys in kernel mode.

## Impact

Successful exploitation allows for the permanent removal of security tooling, persistence mechanism installation, and modification of system-wide security configurations. This technique is particularly dangerous as it occurs during the early boot phase, allowing attackers to neutralize security products before they are fully operational. While research focuses on non-Defender tooling like BTR_CLI, the core risk remains the weaponization of signed kernel drivers to bypass security controls across any affected Windows environment.

## Recommendation

* Deploy the provided Sigma rule to detect the creation of ':changelist' ADS and unauthorized service 'Args' registry modifications.
* Monitor for the assignment of 'SeLoadDriverPrivilege' to non-administrative or suspicious service accounts.
* Conduct threat hunting for the creation of BTR-related feedback artifacts, such as '\\SystemRoot\\Temp\\BootClean.log' or '*.sys:*.dat' ADS files.
* Audit existing Windows services for 'Args' values that reference local NTFS streams, focusing on drivers loaded from non-standard or user-writable directories.
