---
title: Windows Firewall Rule Deletion via Netsh.exe
slug: 2026-09-netsh-firewall-deletion
description: Adversaries utilize the netsh.exe utility to impair host-based security by removing active firewall rules, potentially facilitating unauthorized lateral movement or command-and-control communication.
date: "2026-09-01T12:22:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows
  - sysadmin-tooling
rules:
  - title: Detect Firewall Rule Deletion via Netsh
    description: Detects the removal of a port or application rule in the Windows Firewall configuration using netsh
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to monitor for netsh.exe firewall modifications
      owner: Detection Engineering
      due: 48h
      evidence: Source provides actionable Sigma logic for this TTP
  hunt_leads:
    - lead: Search for historical logs of netsh.exe firewall deletion commands
      technique_id: T1686
      data_needed:
        - process_creation
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Historical TTP visibility
  mitigation_plan:
    - priority: medium
      action: Enforce Windows Firewall GPOs to prevent unauthorized modifications by standard users
      owner: IT Operations
      addresses: T1686
      evidence: Defensive baseline practice
  gaps:
    - Lack of coverage for PowerShell-based firewall manipulation (Remove-NetFirewallRule)
---

Adversaries and malicious software frequently leverage the legitimate Windows command-line utility 'netsh.exe' to modify network security configurations. By executing specific commands, actors can delete firewall port or application rules, thereby disabling critical defense mechanisms. This activity is typically observed during the post-exploitation phase, where an attacker seeks to bypass restrictive network segmentation or security policies to establish persistence or enable C2 traffic. Defenders should distinguish between legitimate administrative maintenance, software updates, and unauthorized modifications initiated by non-standard parent processes.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows system.
2. Attacker performs internal reconnaissance to identify existing firewall rules.
3. Attacker determines a need to disable security filters for a specific port or service.
4. Attacker executes 'netsh.exe' with elevated privileges to modify the Windows Firewall configuration.
5. The command 'netsh firewall delete' or 'netsh advfirewall firewall delete' is issued against specific rules.
6. The Windows Firewall removes the specified rule, creating an open hole in network ingress/egress filtering.
7. Attacker proceeds with malicious objectives, such as lateral movement or exfiltration, unimpeded by previous security rules.

## Impact

Successful deletion of firewall rules impairs host-based security, increasing the probability of successful exploitation, lateral movement, or data exfiltration. If left unmonitored, this activity allows adversaries to maintain long-term access and control within the target network segment.

## Recommendation

- Deploy the provided Sigma rule to monitor process creation events for 'netsh.exe' command-line arguments related to firewall rule deletion.
- Baseline common administrative scripts or software installation processes that frequently modify firewall rules to reduce false positives in the detection logic.
- Enable PowerShell script block logging and process creation (Event ID 1) for visibility into administrative tool execution.
- Audit and restrict administrative access to systems where modification of firewall settings is not required by standard business operations.
