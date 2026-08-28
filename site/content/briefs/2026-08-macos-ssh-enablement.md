---
title: Detection of Unauthorized Remote SSH Service Enablement on macOS
slug: 2026-08-macos-ssh-enablement
description: Adversaries may use the systemsetup or launchctl commands to programmatically enable remote SSH services on macOS to facilitate persistence and lateral movement.
date: "2026-08-28T21:07:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - persistence
  - lateral-movement
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Adversaries may exploit this to gain unauthorized access and move laterally within a network.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1133
    technique_name: External Remote Services
    evidence: The detection rule identifies suspicious use of systemsetup to enable SSH.
    confidence_band: high
rules:
  - title: Detect Unauthorized SSH Remote Login Enablement
    description: Detects the use of systemsetup or launchctl to enable or load the SSH service on macOS, excluding known management tools.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.004
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to identify unauthorized SSH configuration changes.
      owner: Detection Engineering
      due: 48h
---

Adversaries targeting macOS systems may attempt to establish remote access for persistence or lateral movement by enabling the built-in Secure Shell (SSH) service. The standard method for this is the `systemsetup` utility, specifically the `-setremotelogin` argument, or by interacting directly with the `launchctl` service manager to load the SSH daemon (`sshd`). While legitimate administrative tasks (such as those performed by Jamf) frequently require this capability, unauthorized execution of these commands - particularly by non-administrative user accounts - is a high-signal indicator of adversary activity. Defenders should monitor for these process execution patterns to identify configuration changes that deviate from standard deployment baselines.

## Attack Chain

1. The attacker gains initial access to the target macOS host via an exploit or user-executed malware.
2. The attacker identifies that remote management is disabled, limiting their ability to maintain access or move laterally.
3. The attacker executes `systemsetup -setremotelogin on` to enable the SSH service.
4. Alternatively, the attacker uses `launchctl load` to bootstrap `com.openssh.sshd` if `systemsetup` is restricted.
5. The attacker potentially adds an authorized SSH key to the target user's `~/.ssh/authorized_keys` file.
6. The attacker establishes a persistent remote connection to the host using the newly enabled SSH service for command-and-control.
7. The attacker uses the established SSH session to perform internal network reconnaissance and lateral movement.

## Impact

Successful exploitation allows attackers to bypass security controls, maintain long-term persistence on the compromised host, and utilize the host as a jump box to pivot into the internal network. This compromises the confidentiality and integrity of the affected workstation and its associated user accounts.

## Recommendation

1. Deploy the provided Sigma rule to monitor for unauthorized execution of `systemsetup` and `launchctl` for SSH-related configuration changes.
2. Baseline your organization's use of automated administrative tools (e.g., Jamf, Kandji, or custom management scripts) and create specific exclusion filters for these known-good parent processes.
3. Restrict administrative privileges on macOS endpoints to reduce the likelihood of unauthorized users executing system-level configuration changes.
4. Monitor process execution logs for suspicious parent-child relationships, specifically looking for `systemsetup` or `launchctl` spawned by shells or unknown binaries.
