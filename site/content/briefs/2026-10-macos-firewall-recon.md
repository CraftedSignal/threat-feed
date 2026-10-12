---
title: Detection of macOS Firewall Configuration Enumeration
slug: 2026-10-macos-firewall-recon
description: Adversaries may enumerate macOS application firewall settings using legitimate binaries to identify security restrictions and potential network attack surfaces.
date: "2026-10-12T17:52:18Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - macos
  - discovery
  - reconnaissance
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: This analytic detects attempts to enumerate or verify the configuration of the macOS application firewall.
    confidence_band: high
rules:
  - title: Detect macOS Firewall Enumeration
    description: Detects the use of defaults to read application firewall preferences or socketfilterfw to query the global firewall state.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for infrequent execution of firewall utility commands by standard user accounts.
      technique_id: T1016
      data_needed:
        - Process creation events including user and command line.
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Adversaries may leverage them to identify potential attack surfaces.
  mitigation_plan:
    - priority: medium_term
      action: Review and restrict sudo privileges for non-administrative users to limit reconnaissance.
      owner: IT Operations
      addresses: T1016
      evidence: Monitoring for these commands can provide early indication of reconnaissance activity.
---

Adversaries targeting macOS endpoints often engage in network and security configuration discovery to understand the local defensive posture. This threat involves the use of native utilities, specifically the `defaults` command to read the `com.apple.alf` preference domain and the `socketfilterfw` (Application Firewall) binary to query the global firewall state. While these tools are essential for system administration and troubleshooting, their execution by non-privileged users or outside of established maintenance windows can serve as an indicator of attacker reconnaissance. By querying these interfaces, an adversary can determine if the application firewall is active, identify blocked or allowed applications, and map out existing network access policies, which helps them tailor subsequent lateral movement or C2 traffic to evade detection.

## Impact

Successful enumeration of firewall rules allows attackers to identify gaps in the security posture of macOS systems. This intelligence facilitates the selection of stealthier persistence and C2 techniques that are less likely to be blocked by existing local firewall policies, increasing the risk of successful long-term system compromise in corporate environments.

## Recommendation

Deploy detection rules to monitor for the execution of firewall-related reconnaissance commands.
- Implement process creation logging via EndpointSecurity framework or osquery to capture command-line arguments for `defaults` and `socketfilterfw`.
- Deploy the provided Sigma rule to your SIEM to monitor for unauthorized execution of these utilities.
- Baseline administrative activity by identifying and excluding known service accounts, MDM agents, or IT support tools that legitimately query firewall settings.
