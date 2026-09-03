---
title: Detection of Non-Browser DNS Queries to Remote Access Software Domains
slug: 2026-09-dns-query-remote-access
description: Adversaries frequently leverage legitimate remote access and support software to establish command and control channels; detecting these tools via DNS queries from non-browser processes provides visibility into potential unauthorized remote access.
date: "2026-09-03T13:36:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - t1219.002
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: An adversary may use legitimate desktop support and remote access software to establish an interactive command and control channel.
    confidence_band: high
rules:
  - title: Detect DNS Queries to Remote Access Software Domains from Non-Browser Apps
    description: Detects DNS queries to common RMM and remote access tool domains from non-browser processes
    platform: sigma
    severity: medium
    tactics:
      - command-and-control
    data_sources:
      - dns_query
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting non-browser access to known C2 domains.
  hunt_leads:
    - lead: Search for DNS query activity for listed RMM domains originating from non-browser processes.
      technique_id: T1219
      data_needed:
        - DNS query logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sigma source defines these domains as RMM infrastructure often used by threat actors.
---

Adversaries often use legitimate desktop support and remote access tools to establish interactive command and control (C2) channels. These tools are frequently whitelisted by application control policies due to their role in technical support operations. By monitoring DNS queries directed at these specific domains from processes other than authorized web browsers, defenders can identify suspicious execution of Remote Monitoring and Management (RMM) or remote access utilities. This telemetry is critical for identifying unauthorized persistence and lateral movement attempts by threat groups, such as Scattered Spider, which have been observed utilizing various RMM solutions to maintain access.

## Impact

Successful deployment of unauthorized remote access software allows attackers to perform interactive operations, exfiltrate sensitive data, and bypass traditional security controls that trust signed support tools. This activity is a common precursor to ransomware deployment and large-scale data breaches in enterprise environments.

## Recommendation

Deploy the provided Sigma rule to detect DNS queries to RMM domains from non-browser applications.
- Baseline your organization's authorized remote access tools and tune the rule to allowlist sanctioned versions.
- Integrate these findings into your incident response process to verify if the initiated connection was requested by an authorized administrator.
- Review and monitor internal outbound DNS traffic for these specific domains.
