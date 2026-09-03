---
title: Suspicious NTFS Symbolic Link Behavior Modification
slug: 2026-09-ntfs-symlink-behavior
description: Adversaries leverage the Windows fsutil utility to modify NTFS symbolic link evaluation settings, potentially facilitating privilege escalation or lateral movement via unconventional file path resolution.
date: "2026-09-03T13:45:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - execution
  - windows
  - ransomware
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects the modification of NTFS symbolic link behavior using fsutil.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
    evidence: fsutil could be used to enable remote to local or remote to remote symlinks for potential attacks.
    confidence_band: high
rules:
  - title: Detect Suspicious NTFS Symlink Behavior Modification
    description: Detects the modification of NTFS symbolic link behavior using fsutil, which could be used to enable remote to local or remote to remote symlinks for potential attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - execution
    techniques:
      - T1059
      - T1222.001
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
    - action: Deploy Sigma detection rule to monitor for SymlinkEvaluation configuration changes
      owner: Detection Engineering
      due: 48h
      evidence: Source provides actionable Sigma rule for fsutil behavior monitoring
  hunt_leads:
    - lead: Search historical logs for fsutil command-line arguments related to SymlinkEvaluation
      technique_id: T1222.001
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique is frequently used by ransomware actors for lateral movement
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution of fsutil.exe to privileged service accounts only
      owner: IT Operations
      addresses: Defense impairment via symlink modification
      evidence: Standard security hardening for Windows environments
---

Threat actors, including those deploying ransomware such as BlackCat (ALPHV) and RansomHub, have been observed utilizing the Windows `fsutil` utility to modify the operating system's handling of symbolic links. By altering the `SymlinkEvaluation` behavior settings, attackers can enable Local-to-Local (L2L), Remote-to-Local (R2L), or Remote-to-Remote (R2R) symlink resolution. This capability allows for the creation of links that point to sensitive files or directories across network shares, which are typically restricted by default security configurations. This technique is often used as part of a post-exploitation phase to bypass security controls or to facilitate the exfiltration of sensitive data that would otherwise be protected by standard path-based access control lists. Defenders should monitor for command-line arguments that explicitly change these registry-backed security settings.

## Attack Chain

1. Initial access is established on a Windows endpoint, often via phishing or exploited services.
2. The attacker executes a command shell (cmd.exe or PowerShell) under a privileged context.
3. The attacker identifies network shares or local directories to target for lateral movement or data staging.
4. The attacker runs `fsutil behavior set SymlinkEvaluation` to modify the system's policy to allow R2L or R2R symlinks.
5. The attacker creates a malicious symbolic link using `mklink` or PowerShell commands that leverage the modified evaluation policy.
6. The system interprets the symbolic link based on the updated `fsutil` configuration, allowing access to the targeted remote or local resource.
7. The attacker reads or exfiltrates the sensitive files accessed through the symlink.
8. The final objective is reached, such as the deployment of ransomware or exfiltration of proprietary credentials.

## Impact

The unauthorized modification of NTFS symlink behavior can lead to privilege escalation and unauthorized access to data across network boundaries. Observed campaigns, such as those involving RansomHub and BlackCat, demonstrate that this technique is a key component in the broader workflow of reconnaissance and data compromise within enterprise environments, frequently resulting in widespread encryption and data theft.

## Recommendation

* Deploy the provided Sigma rule to detect processes executing `fsutil behavior set SymlinkEvaluation` with parameters that enable risky symlink resolution.
* Monitor process creation logs (Event ID 1) for parent processes originating from unexpected locations (e.g., non-standard user profile paths or TEMP directories).
* Restrict the use of the `fsutil` utility to authorized administrative accounts and block execution for standard user accounts.
* Investigate the parent process of any `fsutil` execution to determine if it stems from legitimate system administration tooling or malicious activity.
