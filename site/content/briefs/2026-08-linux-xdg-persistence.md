---
title: Linux XDG Autostart Persistence Mechanism
slug: 2026-08-linux-xdg-persistence
description: Adversaries, including those using the PANIX post-exploitation framework, are abusing XDG autostart directories on Linux to achieve persistence via malicious .desktop files.
date: "2026-08-07T15:18:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - post-exploitation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Adversaries abuse XDG autostart entries to achieve persistence on Linux desktop environments.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: Any .desktop file placed in these directories is automatically executed when a user logs into a graphical session.
    confidence_band: high
rules:
  - title: Detect Suspicious XDG Autostart File Creation
    description: Detects the creation of .desktop files within standard XDG autostart directories, which is a common persistence technique on Linux.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547
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
    - action: Deploy file monitoring for /etc/xdg/autostart/ and ~/.config/autostart/ paths.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic requirement for file-based detection.
  hunt_leads:
    - lead: Audit current contents of XDG autostart directories for non-standard binaries.
      technique_id: T1547
      data_needed:
        - File list of /etc/xdg/autostart/ and ~/.config/autostart/
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique allows for trivial persistence that should be manually reviewed.
---

Adversaries targeting Linux environments are leveraging XDG autostart directories to establish persistence by creating or modifying .desktop files. These directories, specifically /etc/xdg/autostart for system-wide configuration and ~/.config/autostart for user-specific sessions, are monitored by Linux desktop environments to automatically execute applications upon user login. This technique is utilized by various post-exploitation frameworks, such as PANIX, to maintain access across reboots. By placing a malicious .desktop file in these locations, an attacker ensures their payload executes with the privileges of the logged-in user. Defenders should prioritize monitoring for file creation events within these specific paths to identify unauthorized persistence attempts, while filtering against legitimate software installations that utilize these paths for standard application startup.

## Attack Chain

1. Attacker gains initial access to the Linux system using an exploit or compromised credentials.
2. Attacker performs local reconnaissance to identify the user's desktop environment and home directory.
3. Attacker stages a malicious payload (e.g., a script or binary) on the file system.
4. Attacker crafts a malicious .desktop file that references the staged payload in the Exec field.
5. Attacker writes the .desktop file to the ~/.config/autostart/ directory for user-local persistence.
6. Attacker optionally writes to /etc/xdg/autostart/ if root privileges were obtained for system-wide persistence.
7. Attacker waits for the user to log into their graphical desktop session.
8. Desktop environment automatically parses the .desktop file and executes the malicious payload, re-establishing access for the attacker.

## Impact

Successful exploitation allows for long-term persistence on Linux desktop environments, enabling attackers to maintain command-and-control access after system reboots. This technique effectively bypasses simple session-based defenses and ensures that malicious code runs with the context and permissions of the targeted user upon every login.

## Recommendation

- Implement file integrity monitoring for the paths /etc/xdg/autostart/ and ~/.config/autostart/ to alert on the creation of any .desktop file.
- Deploy the provided Sigma rule to ingest Sysmon for Linux file creation events and correlate them with process execution telemetry.
- Establish an allowlist for known-good software deployment tools that legitimately modify autostart directories to reduce false positive noise.
- Audit existing .desktop files in these directories for suspicious Exec commands that deviate from standard installed application paths.
