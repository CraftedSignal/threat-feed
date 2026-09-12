---
title: Suspicious DNS Activity to High-Risk Top-Level Domains
slug: 2026-09-suspicious-tld-dns
description: This detection identifies suspicious DNS queries from Windows processes to high-risk top-level domains commonly used for command and control infrastructure.
date: "2026-09-12T00:50:11Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Identifies DNS queries to commonly abused Top Level Domains by common LOLBINs.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This behavior matches on common malware C2 abusing less formal domain names.
    confidence_band: high
rules:
  - title: Detect Network Activity to a Suspicious Top Level Domain
    description: Detects DNS queries to high-risk TLDs from known LOLBins or suspicious/unsigned binaries on Windows hosts.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to monitor high-risk TLD queries.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify processes executing from C:\Users\Public or C:\ProgramData performing network activity.
      technique_id: T1071.004
      priority: medium
      disposition: hunt_now
  mitigation_plan:
    - priority: medium
      action: Implement DNS filtering to block known malicious high-risk TLDs at the resolver level.
      owner: IT Operations
---

This detection identifies DNS queries directed toward high-risk Top Level Domains (TLDs) such as .top, .xyz, .onion, and .click originating from Windows endpoints. Malicious actors frequently leverage these less restrictive TLDs to host command and control (C2) infrastructure and phishing landing pages. The detection logic triggers when specific Living-off-the-Land binaries (LOLBins) - including powershell.exe, rundll32.exe, mshta.exe, and others - or unsigned and suspiciously located binaries (such as those in C:\\Users\\Public or C:\\ProgramData) perform these lookups. This behavior is a common indicator of unauthorized network communication or staging activity. Defenders should investigate these events to differentiate between malicious C2 beacons and legitimate developer or security tooling. The rule is tuned to ignore established Microsoft Defender update traffic, reducing noise in enterprise environments.

## Impact

Successful exploitation of the network by C2 infrastructure using these TLDs can lead to unauthorized data exfiltration, remote command execution, or the deployment of secondary payloads. By monitoring these specific domain patterns, organizations can intercept attacker communication at the early stages of a campaign before significant damage is sustained.

## Recommendation

- Deploy the provided detection logic to your SIEM/EDR platform to monitor for DNS activity to the listed high-risk TLDs.
- Prioritize alerts where the originating process is unsigned or resides in a user-writable directory (e.g., C:\\Users\\Public\\).
- Cross-reference DNS queries with subsequent network connection events to the resolved IPs to confirm active C2 communication.
- Investigate the process launch chain for suspicious parents, such as document-handling applications or browser processes starting scripting engines.
- Tune the detection by creating exceptions based on process signature and host-specific administrative workflows rather than suppressing the TLD or process name globally.
