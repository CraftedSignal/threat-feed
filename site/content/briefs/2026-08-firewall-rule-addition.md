---
title: Detection of Unauthorized Windows Firewall Exception Rule Creation
slug: 2026-08-firewall-rule-addition
description: Monitoring for non-standard additions to the Windows Defender Firewall exception list to identify potential defense impairment activity by unauthorized processes.
date: "2026-08-13T10:33:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - windows-firewall
  - monitoring
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server
rules:
  - title: Detect Uncommon New Firewall Rule Addition
    description: Detects when a rule has been added to the Windows Defender Firewall exception list from non-standard locations or by unauthorized processes.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - process_creation
      - windows
      - firewall-as
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Windows Firewall audit logging
      owner: IT Operations
      due: 72h
      evidence: Required for Event IDs 2004, 2071, 2097
  hunt_leads:
    - lead: Search for existing firewall rules pointing to non-standard paths
      technique_id: T1686.003
      data_needed:
        - Get-NetFirewallRule
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Firewall rules pointing to temp or public directories are high-risk
  mitigation_plan:
    - priority: medium_term
      action: Restrict firewall configuration permissions to administrative groups
      owner: IT Operations
      addresses: T1686.003
      evidence: Limiting modification rights prevents unauthorized rule injection
---

This brief addresses the detection of unauthorized modifications to the Windows Defender Firewall exception list. Attackers often attempt to modify firewall rules to maintain persistence or establish inbound network communication for command-and-control (C2) infrastructure. By adding an exception rule for a malicious binary, an adversary can bypass security controls that would otherwise block their traffic. 

Defenders should monitor Event IDs 2004, 2071, and 2097, which record the creation of new firewall rules. Because many legitimate applications and Windows services perform these actions, it is necessary to filter against known-good paths and trusted system binaries. This brief provides a detection logic to isolate modifications occurring outside of standard enterprise application paths or those performed by suspicious processes. Monitoring these events is a critical component of identifying defense impairment and lateral movement attempts.

## Impact

Successful exploitation allows an attacker to open communication ports that bypass firewall restrictions, potentially enabling unhindered C2 communication or lateral movement between compromised hosts within an internal network. If not monitored, these rule modifications may remain undetected as a form of stealthy persistence.

## Recommendation

- Deploy the Sigma rule below to monitor for firewall rule additions originating from suspicious paths or untrusted modifying applications.
- Baseline common administrative tools and deployment scripts in your environment to further reduce false positives before enabling alerting.
- Review Event ID 2004, 2071, and 2097 logs periodically to identify unusual network exceptions or rule additions occurring outside of standard maintenance windows.
