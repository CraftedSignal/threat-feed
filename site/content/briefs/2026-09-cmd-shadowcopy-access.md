---
title: Detection of Registry Hive Exfiltration via Volume Shadow Copy
slug: 2026-09-cmd-shadowcopy-access
description: Adversaries use the Windows 'copy' command to exfiltrate sensitive files, such as registry hives, by accessing data from Volume Shadow Copy Service snapshots.
date: "2026-09-03T12:37:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-theft
  - persistence
  - windows
  - forensics
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Detects the execution of the builtin 'copy' command that targets a shadow copy (sometimes used to copy registry hives that are in use)
    confidence_band: high
rules:
  - title: Detect Copying Sensitive Files from Volume Shadow Copy
    description: Detects the execution of the builtin 'copy' command that targets a shadow copy path, often used to steal locked registry hives.
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
    - action: Deploy Sigma rule to detect registry hive exfiltration attempts
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief
  hunt_leads:
    - lead: Search logs for any usage of vssadmin or 'copy' commands pointing to GLOBALROOT device paths
      technique_id: T1490
      data_needed:
        - Process creation logs (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this as a primary indicator of registry theft
  mitigation_plan:
    - priority: short_term
      action: Restrict administrative rights on endpoints to limit shadow copy creation and file access
      owner: IT Operations
      addresses: Privilege escalation and credential theft
      evidence: Standard hardening practices
---

Threat actors frequently target the Windows registry hives (SAM, SYSTEM, SECURITY) to extract password hashes for offline cracking or lateral movement. Because these files are locked by the operating system during active sessions, attackers utilize the Volume Shadow Copy Service (VSS) to create snapshots of the disk. By mounting these snapshots using the \\?\GLOBALROOT device path, attackers can bypass file locks to copy protected files. This technique is commonly observed in post-exploitation phases where attackers aim to escalate privileges or move laterally through the environment. Defending against this requires monitoring for direct command-line access to VSS device paths via common file utilities.

## Attack Chain

1. Attacker gains administrative access to the target endpoint.
2. Attacker executes vssadmin or similar tools to create a new volume shadow copy.
3. Attacker identifies the device path of the newly created shadow copy (e.g., \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX).
4. Attacker constructs a copy command targeting the sensitive file path within the shadow copy device mount.
5. Attacker executes 'cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SYSTEM C:\Temp\SYSTEM'.
6. The OS allows the copy operation because the file is read from a snapshot rather than the live locked registry hive.
7. Attacker exfiltrates the copied hive files to an external C2 or staging area for local analysis.

## Impact

Successful execution of this technique allows attackers to obtain critical credentials (e.g., NTLM hashes or Kerberos keys) stored in the registry. This often leads to full domain compromise, as the attacker can perform pass-the-hash attacks or use the stolen credentials to impersonate high-privilege service accounts.

## Recommendation

Deploy the provided Sigma rule to detect the specific use of the 'copy' command against VSS device paths. Configure EDR or Sysmon to log all command-line arguments (Event ID 1). Audit usage of administrative tools like vssadmin to detect the creation of snapshots prior to the file copy operation.
