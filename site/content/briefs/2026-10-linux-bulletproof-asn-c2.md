---
title: Suspicious Linux Outbound Connections to Bulletproof Hosting ASNs
slug: 2026-10-linux-bulletproof-asn-c2
description: This detection logic identifies outbound network connections from Linux hosts originating from anomalous locations or via suspicious binaries to ASNs associated with bulletproof or high-abuse hosting providers.
date: "2026-10-07T10:30:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-and-control
  - linux
  - networking
  - detection-engineering
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Adversaries often stage payloads in world-writable or web directories and beacon to infrastructure that ignores abuse reports.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule flags a Linux process that initiates an outbound connection... or it is a downloader, shell, or interpreter frequently abused to fetch and launch follow-on payloads.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1071/
  - https://www.spamhaus.org/blocklists/do-not-route-or-peer/
rules:
  - title: Suspicious Linux Process Connection to Bulletproof Hosting ASN
    description: Detects outbound connection attempts from unusual Linux process locations or common living-off-the-land utilities to ASNs associated with bulletproof or high-abuse hosting.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy and tune the detection rule to match your known-good infrastructure.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify all processes executing from /tmp, /var/tmp, or web directories that have initiated network connections.
      technique_id: T1059
      data_needed:
        - Process creation logs
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
---

This threat brief describes detection logic aimed at identifying command-and-control (C2) activity and staging of payloads within Linux environments. Adversaries frequently leverage high-abuse or bulletproof hosting providers, such as Storm Industries, Ecatel, Aeza, and Proton66, to host malicious infrastructure that ignores abuse reports. The detection focuses on outbound connections triggered by living-off-the-land (LotL) binaries (e.g., curl, wget, python, or various shell interpreters) or processes executing from non-standard, world-writable, or web-accessible directories such as /tmp, /dev/shm, /var/www, and memfd. This activity is often a strong indicator of initial payload retrieval, webshell operation, or persistent C2 beaconing. Defenders should validate that outbound traffic to these specific high-risk ASNs aligns with approved administrative or business requirements, as many of these providers lack robust abuse-handling policies.

## Impact

Successful exploitation of these patterns can lead to unauthorized remote command execution, persistent backdoor access, exfiltration of sensitive data, or the deployment of secondary malicious payloads. Compromise of Linux systems, particularly those exposed to the internet, may result in widespread network traversal or the conversion of the host into a node for further malicious operations, with potential damage to system integrity and data confidentiality.

## Recommendation

- Enable comprehensive network and process-creation logging to identify outbound connections from non-standard directories.
- Implement and tune the provided detection logic to monitor traffic destined for high-abuse ASNs.
- Investigate any process initiated from /tmp, /var/tmp, or web directories that maintains persistent connections to unknown external IP addresses.
- Block identified high-abuse ASNs at the network perimeter (DNS, firewall, proxy) where business operations permit.
- Conduct regular audits of public-facing web directories to identify and remove unauthorized webshells or staged ELF binaries.
