---
title: ShieldBreak Local Privilege Escalation via NTFS Alternate Data Streams
slug: 2026-08-shieldbreak
description: The ShieldBreak exploit abuses symbolic link swaps over local loopback SMB shares to create NTFS Alternate Data Streams, enabling privilege escalation by redirecting privileged file writes to system-critical directories.
date: "2026-08-20T19:06:23Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - shieldbreak
  - rogueplanet
  - privilege-escalation
  - windows
  - ads
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564.004
    technique_name: 'Hide Artifacts: NTFS File Attributes'
    evidence: The exploit abuses a symbolic link swap through a loopback share to redirect a privileged, Defender-driven write into an alternate data stream on a system-owned file.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
    evidence: The following analytic detects the creation of an NTFS alternate data stream (ADS) accessed over a local administrative share targeting the loopback address (127.0.0.1).
    confidence_band: high
references:
  - https://www.cyderes.com/howler-cell/rogueplanet-windows-zero-day
  - https://www.threatlocker.com/blog/nightmareeclipse-releases-new-poc-shieldbreak-exploits-same-weakness-as-rogueplanet
rules:
  - title: Detect NTFS Alternate Data Stream Creation over Loopback Share
    description: Detects the creation of an NTFS alternate data stream (ADS) accessed over a local administrative share targeting the loopback address 127.0.0.1.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1021.002
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
    - action: Enable Object Access auditing for File Shares via GPO
      owner: IT Operations
      due: 48h
      evidence: Required for Event ID 5145 population.
  hunt_leads:
    - lead: Search for Event ID 5145 where IpAddress is 127.0.0.1
      technique_id: T1021.002
      data_needed:
        - Security logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Anomalous loopback access to admin shares is a hallmark of ShieldBreak.
  mitigation_plan:
    - priority: medium_term
      action: Strictly enforce file integrity monitoring on system-critical directories
      owner: Endpoint Security Team
      addresses: T1564.004
      evidence: ShieldBreak target files include system-owned files.
---

ShieldBreak is an exploit technique that achieves local privilege escalation (LPE) by manipulating how the Windows operating system handles file operations. Discovered in the context of the RoguePlanet threat landscape, the exploit targets the interaction between privileged, Defender-driven write operations and local SMB shares. By initiating a connection to the loopback address (127.0.0.1) and performing a symbolic link swap, an attacker can trick the system into redirecting these writes into an NTFS alternate data stream (ADS) on a target file. This manipulation allows for the injection of attacker-controlled content into protected locations, such as C:\Windows\System32. The technique is significant for defenders because it blends legitimate administrative share access with abnormal local loopback usage to evade traditional file-integrity monitoring.

## Attack Chain

1. Attacker establishes a local SMB connection to the target system via the loopback address (127.0.0.1).
2. The attacker identifies a target file path for a future privileged write operation.
3. A symbolic link is created or swapped to map the target file path to a location under the attacker's control.
4. The attacker triggers a legitimate, privileged process (e.g., Windows Defender) to perform a write operation to the initial path.
5. The OS follows the symbolic link, redirecting the privileged write to the attacker-defined target via an ADS.
6. The payload is successfully written into an alternate data stream within a sensitive directory, such as C:\Windows\System32.
7. The attacker leverages the dropped payload to execute code with elevated system privileges.

## Impact

Successful exploitation of ShieldBreak results in local privilege escalation, allowing an attacker to move from a standard user context to full administrative or SYSTEM-level control of the target host. By compromising the integrity of files in C:\Windows\System32, attackers can achieve persistent, elevated execution that is difficult to detect without deep inspection of NTFS stream objects. This technique has been observed in the wild in the context of the RoguePlanet activity cluster.

## Recommendation

1. Enable Windows Security Event ID 5145 (Object Access auditing for File Shares) in Group Policy to capture SMB access attempts.
2. Deploy the provided Sigma rule to detect the creation of ADS over local administrative loopback shares.
3. Audit existing file integrity monitoring configurations to specifically account for files containing colon-suffixed names, which indicate the presence of alternate data streams.
4. Investigate any instances of 127.0.0.1 access to administrative shares (e.g., ADMIN$, C$) as these are highly anomalous and rarely occur in production environments.
