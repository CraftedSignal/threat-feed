---
title: Detection of Linux System Network Configuration Discovery
slug: 2026-10-linux-network-discovery
description: This detection identifies reconnaissance activity on Linux systems by monitoring for the rapid execution of common network diagnostic tools via Auditd syscall events.
date: "2026-10-12T17:49:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - linux
  - reconnaissance
  - auditd
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: The following analytic detects suspicious system network configuration discovery activities, which may indicate an adversary's attempt to gather information about the network environment.
    confidence_band: high
references:
  - https://www.splunk.com/en_us/blog/security/deep-dive-on-persistence-privilege-escalation-technique-and-detection-in-linux-platform.html
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1016/T1016.yaml#L33
rules:
  - title: Detect Linux System Network Configuration Discovery
    description: Detects multiple network diagnostic commands executed on a Linux host within a short timeframe, indicating potential reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the analytic to the SIEM and baseline administrative usage of network tools.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify hosts executing 4+ unique network configuration tools within 15 minutes.
      technique_id: T1016
      data_needed:
        - Auditd SYSCALL logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic detects 4 or more unique commands in 15m.
---

This detection analytic identifies suspicious system network configuration discovery activities on Linux endpoints, which often serve as a precursor to lateral movement or data exfiltration. Adversaries frequently leverage built-in Linux utilities to map network interfaces, routing tables, and active connections to understand the target network architecture. By monitoring Linux Auditd syscall logs for a threshold of four or more distinct network configuration tools - such as 'arp', 'ifconfig', 'ip', 'netstat', 'iptables', 'ss', or 'route' - within a 15-minute window, this analytic allows security operations teams to detect reconnaissance efforts. This visibility is critical for identifying potential post-compromise activity and mitigating risks before an attacker progresses further into the environment.

## Impact

Successful reconnaissance allows an attacker to identify high-value targets, map internal network segmentation, and discover accessible services or egress paths. This information significantly increases the likelihood of successful lateral movement, privilege escalation, and subsequent data exfiltration within an enterprise environment.

## Recommendation

* Deploy the provided detection logic to monitor Auditd syscall events for clusters of network discovery commands.
* Ingest Linux Auditd data using the Splunk Add-on for Unix and Linux, ensuring correct parsing of SYSCALL, TYPE, EXECVE, and PROCTITLE events.
* Normalize logs according to the Splunk Common Information Model (CIM) to ensure consistent field mapping.
* Tune filter macros in the analytic to exclude known administrative or automation scripts that perform legitimate network diagnostic tasks in your environment.
