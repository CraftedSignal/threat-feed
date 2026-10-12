---
title: Detection of Shadow Storage Volume Manipulation via Vssadmin
slug: 2026-10-resize-shadowstorage
description: Threat actors deploying ransomware such as CLOP, BlackByte, and Medusa manipulate Windows shadow storage volumes using vssadmin.exe to prevent data recovery.
date: "2026-10-12T17:56:25Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - CLOP
tags:
  - ransomware
  - impact
  - windows
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
    evidence: The following analytic identifies the resizing of shadow storage volumes, a technique used by ransomware like CLOP to prevent the recreation of shadow volumes.
    confidence_band: high
rules:
  - title: Detect Shadow Storage Volume Resizing
    description: Detects the use of vssadmin.exe to resize shadow storage, a technique often used by ransomware to hinder data recovery.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 24h
      evidence: High confidence TTP for ransomware readiness.
  hunt_leads:
    - lead: Search for vssadmin.exe execution patterns in historical logs.
      technique_id: T1490
      data_needed:
        - Endpoint process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: T1490 is a core component of modern ransomware operations.
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution of vssadmin.exe to authorized administrative accounts only.
      owner: IT Operations
      addresses: T1490
      evidence: Source documentation on administrative vssadmin usage.
---

Adversaries, specifically those deploying ransomware families including CLOP, BlackByte, Medusa, and VanHelsing, frequently target Windows Volume Shadow Copy Service (VSS) to hinder incident response and data recovery. A primary technique involves using the built-in Windows utility 'vssadmin.exe' to resize or delete existing shadow storage volumes. By setting the maximum size of the shadow storage to a critically low value, attackers ensure that the operating system cannot maintain previous versions of files, effectively neutralizing the built-in recovery mechanism. This behavior is typically observed in the later stages of an intrusion, just prior to final file encryption and the deployment of a ransom note. Monitoring for the execution of vssadmin.exe with arguments related to resizing operations is critical for early detection of imminent ransomware impact.

## Attack Chain

1. Initial access is established via phishing or exploitation of internet-facing vulnerabilities.
2. The attacker performs lateral movement to gain elevated privileges (System/Administrator).
3. The attacker executes discovery commands to identify backup mechanisms and shadow volume configurations.
4. The attacker triggers a command-line process (cmd.exe, powershell.exe, or wmic.exe) to execute vssadmin.exe.
5. The vssadmin command is executed with 'resize' and 'shadowstorage' parameters and the '/maxsize' flag to shrink the available storage.
6. The operating system deletes or truncates existing shadow copies due to the new size constraint.
7. The attacker proceeds to encrypt the file system, having successfully eliminated local recovery options.
8. A ransom note is displayed, and exfiltration of sensitive data occurs if not already completed.

## Impact

Successful manipulation of shadow storage volumes significantly increases the impact of ransomware attacks. By eliminating the ability to restore files from Volume Shadow Copies, organizations are forced to rely on offline backups or pay the ransom to recover encrypted assets. This technique has been observed across multiple ransomware campaigns targeting enterprise environments, leading to prolonged downtime and the potential for irreversible data loss.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious process-creation events involving vssadmin.exe and volume resizing arguments.
* Enable Sysmon (Event ID 1) or Windows Security Log (Event ID 4688) logging to capture detailed command-line arguments for all sensitive administrative utilities.
* Implement an allow-list or monitoring policy for administrative tools used for disk/volume management to identify unauthorized usage in production environments.
