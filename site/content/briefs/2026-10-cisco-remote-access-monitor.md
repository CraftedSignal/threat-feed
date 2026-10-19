---
title: Detection of Unauthorized Remote Access Software via Cisco Secure Firewall
slug: 2026-10-cisco-remote-access-monitor
description: This brief provides detection logic for identifying network traffic associated with dual-use remote access tools like AnyDesk, TeamViewer, and LogMeIn within Cisco Secure Firewall logs.
date: "2026-10-19T13:56:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cisco
  - network-security
  - command-and-control
  - remote-access
vendors:
  - Cisco
products:
  - Secure Firewall
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: The analytic detects network traffic associated with known remote access software applications that are covered by Cisco Secure Firewall Application Detectors.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy analytic logic for Cisco Secure Firewall connection logs
      owner: Detection Engineering
      due: 48h
      evidence: Analytic requires Cisco Secure Firewall ConnectionEvent EventType.
  hunt_leads:
    - lead: Identify endpoints initiating connections to known remote access software update or relay IPs
      technique_id: T1219
      data_needed:
        - Cisco Secure Firewall Connection logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Legitimate remote access software commonly uses specific infrastructure that can be mapped to business processes.
  mitigation_plan:
    - priority: medium
      action: Implement application control policy to restrict remote access tools to authorized IT assets
      owner: IT Operations
      addresses: T1219
      evidence: Restricting dual-use tools prevents unauthorized lateral movement and C2 persistence.
---

This detection focuses on identifying the presence of known remote access software (RAS) within corporate network traffic. Adversaries frequently abuse these legitimate applications to maintain command and control (C2), bypass perimeter defenses, and facilitate unauthorized remote management of compromised hosts. By utilizing Cisco Secure Firewall Application Detectors, security teams can pinpoint connections initiated by tools such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer. Because these applications are often used for legitimate administrative or support tasks, successful implementation requires the use of asset and identity (A&I) lookups and an exceptions list to distinguish between authorized operational use and potentially malicious activity.

## Attack Chain

1. Initial access is achieved via spearphishing, credential harvesting, or exploitation of public-facing assets.
2. The attacker installs or executes a dual-use remote access application (e.g., AnyDesk, TeamViewer) on the target host.
3. The application establishes an outbound connection to its respective C2 infrastructure.
4. The network perimeter (Cisco Secure Firewall) logs the connection event identifying the specific client application.
5. The attacker authenticates to the remote host using the established tunnel.
6. The attacker performs lateral movement, data exfiltration, or deploys follow-on payloads such as ransomware.

## Impact

Successful deployment of unauthorized remote access software provides adversaries with persistent, stealthy access to internal resources. This allows for long-term intelligence gathering, data exfiltration, or the deployment of ransomware. Historically, these tools have been observed in campaigns by actors such as Scattered Spider and various ransomware syndicates, often acting as a precursor to widespread domain compromise and business disruption.

## Recommendation

* Ingest Cisco Secure Firewall Threat Defense logs into your SIEM using the Splunk Add-on for Cisco Security Cloud.
* Implement a lookup-based monitoring strategy to flag traffic associated with the `remote_access_software` category.
* Maintain a `remote_software_exceptions` KVStore collection or CSV lookup to filter out legitimate business tools used by authorized IT and support teams.
* Investigate flagged connections that originate from non-administrative segments or hosts with no prior business justification for using external remote control software.
* Prioritize alerts where the source host has other associated risk events within the last 7 days.
