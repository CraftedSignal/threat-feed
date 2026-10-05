---
title: Detection of Unauthorized Remote Access Software Usage via DNS
slug: 2026-10-remote-access-software-usage
description: This detection analytic identifies unauthorized usage of remote access software by monitoring DNS queries directed at domains associated with tools such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer.
date: "2026-10-05T12:34:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - remote-access
  - dns-monitoring
  - t1219
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries often use these tools to maintain access and control over compromised environments.
    confidence_band: high
rules:
  - title: Detect Remote Access Software DNS Queries
    description: Detects DNS queries to domains associated with known remote access software providers, often used for unauthorized C2 or persistent access.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - dns_query
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy DNS query detection rule.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides analytic methodology for identifying T1219 via DNS logs.
  hunt_leads:
    - lead: Identify all historical DNS traffic to known remote access domains.
      technique_id: T1219
      data_needed:
        - DNS query logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source identifies this as a primary mechanism for T1219 discovery.
  mitigation_plan:
    - priority: medium
      action: Implement application control policies to block unauthorized remote access software execution.
      owner: IT Operations
      addresses: T1219
      evidence: Mitigation of remote access software usage reduces risk of C2 and persistence.
---

Adversaries frequently abuse legitimate remote access software, such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer, to maintain persistent access and command-and-control (C2) within compromised environments. By utilizing these dual-use utilities, attackers can bypass traditional security controls that might otherwise flag custom malware. This analytic focuses on detecting the DNS resolution phase of these connections, which is often the first network-observable indicator of such software being initiated. Detecting this activity is vital for a Security Operations Center (SOC) because unauthorized remote access is commonly a precursor to data exfiltration, ransomware attacks, and full-scale network compromise. Defenders should prioritize identifying these requests, particularly when the remote access software is not sanctioned for use by IT or security teams within the enterprise.

## Impact

Successful deployment of unauthorized remote access tools allows attackers to maintain stealthy persistence, bypass ingress filtering, and remotely execute commands on compromised endpoints. This behavior has been observed across various high-impact threat campaigns, including ransomware operations and activities attributed to groups like Scattered Spider. If left undetected, this activity can facilitate large-scale data breaches and operational disruption.

## Recommendation

Prioritize the implementation of DNS-based visibility to identify unauthorized remote access utilities.
* Deploy the detection logic to monitor DNS query logs for domains associated with unauthorized remote access software providers.
* Use the "remote_access_software_usage_exceptions" macro to maintain a list of sanctioned remote access tools to minimize false positives.
* Integrate an Assets and Identities (A&I) lookup to differentiate between authorized administrative use and suspicious activity originating from unexpected hosts.
* Investigate triggered alerts using the provided drilldown search to identify the source endpoint and assess the scope of the potential compromise.
