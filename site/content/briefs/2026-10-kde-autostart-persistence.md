---
title: KDE AutoStart Persistence Mechanism Abuse
slug: 2026-10-kde-autostart-persistence
description: Adversaries leverage KDE AutoStart scripts and desktop files to achieve persistence on Linux systems by ensuring malicious code executes automatically upon user logon.
date: "2026-10-05T17:57:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - kde
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries may abuse this method for persistence.
    confidence_band: high
rules:
  - title: Detect KDE AutoStart Script or Desktop File Creation
    description: Detects the creation or modification of .sh or .desktop files in known KDE AutoStart directories, which is a common persistence technique.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor KDE Autostart directories
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific paths and file extensions for monitoring.
  hunt_leads:
    - lead: Audit existing files in ~/.config/autostart/ and /etc/xdg/autostart/
      technique_id: T1547.001
      data_needed:
        - File listing for autostart directories
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies these as common paths for persistence.
  mitigation_plan:
    - priority: medium_term
      action: Enforce file integrity monitoring (FIM) on user configuration directories.
      owner: IT Operations
      addresses: T1547.001
      evidence: Source suggests monitoring as a primary defense.
---

Adversaries targeting Linux systems often seek to maintain access across reboots and logons by abusing native desktop environment functionality. The K Desktop Environment (KDE) provides a built-in AutoStart feature, intended to launch user-specified applications or scripts when a session begins. By placing malicious shell scripts (.sh) or desktop configuration files (.desktop) into specific directories - such as ~/.config/autostart/, ~/.kde/Autostart/, or /etc/xdg/autostart/ - an attacker can ensure their payload executes with the privileges of the logged-in user. This technique is a well-documented method for achieving persistence, observed in various threat campaigns. Defenders should monitor for unexpected file creation or modification events within these high-risk AutoStart paths, as legitimate software rarely modifies these locations after initial installation.

## Attack Chain

1. Attacker gains initial access to the Linux host via exploitation or credential compromise.
2. Attacker performs local reconnaissance to identify the desktop environment and user session directories.
3. Attacker identifies the appropriate AutoStart directory (e.g., ~/.config/autostart/ or ~/.local/share/autostart/).
4. Attacker writes a malicious payload or a script designed to download and execute secondary stages to the target directory.
5. Attacker creates or modifies a .desktop file or .sh script to point to the malicious payload, ensuring correct permissions (e.g., chmod +x).
6. The victim user logs into their KDE desktop session.
7. The KDE session manager automatically executes the malicious script or file, granting the attacker persistence.

## Impact

Successful abuse of this technique allows an attacker to maintain a foothold on a compromised Linux system, facilitating ongoing exfiltration of sensitive data, monitoring of user activity, and execution of lateral movement tools. This persistence mechanism is difficult to detect without dedicated monitoring of file system events in specific user configuration directories.

## Recommendation

Prioritize the identification of unauthorized modifications to KDE Autostart directories.
- Deploy the provided Sigma rule to monitor file_event activity targeting AutoStart directories.
- Implement periodic auditing of the file system using Osquery to list files in known autostart paths and compare them against a baseline of legitimate entries.
- Investigate any newly created .sh or .desktop files in user home directories for suspicious content, such as encoded commands or external network connection attempts.
- Use file integrity monitoring (FIM) or auditd to alert on any write events to /etc/xdg/autostart/ or user-specific .config/autostart/ paths.
