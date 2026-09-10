---
title: Cross-Platform C2 Detection via Suricata and Elastic Defend Correlation
slug: 2026-09-suricata-elastic-correlation
description: This detection capability correlates network-layer Suricata alerts with host-based process telemetry from Elastic Defend to identify malicious outbound command and control communication.
date: "2026-09-10T18:47:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - detection-engineering
  - network-security
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This detection correlates Suricata alerts with Elastic Defend network events to identify the source process performing the network activity.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
    evidence: The rule identifies network activity via non-standard ports.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: The rule identifies network service discovery activity.
    confidence_band: high
references:
  - https://attack.mitre.org/tactics/TA0011/
  - https://www.elastic.co/docs/reference/integrations/suricata
  - https://www.elastic.co/docs/reference/integrations/endpoint
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy correlation logic in SIEM to bridge Suricata and Elastic Defend network logs
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for network-to-process correlation.
  mitigation_plan:
    - priority: short_term
      action: Tune alert filters to exclude known administrative processes like PDQ Inventory
      owner: SOC
      addresses: False positives in administrative network activity
      evidence: Source documentation identifies specific administrative software to exclude from correlation.
---

This detection framework enables security teams to correlate network security alerts from Suricata with host-level process execution data captured by Elastic Defend. By linking network-layer indicators, such as application-layer protocol anomalies or non-standard port usage, to the specific process ID and executable responsible for the traffic, analysts can reduce noise and improve the accuracy of command and control (C2) detection. This capability is cross-platform, supporting Windows, Linux, and macOS environments. The methodology is designed to identify beaconing or unauthorized network discovery activity that would otherwise remain siloed within network logs, allowing defenders to pinpoint the exact source process, path, and command-line parameters associated with flagged network traffic.

## Impact

Successful implementation of this detection strategy allows for the identification of previously obscured C2 and discovery activity, limiting the potential for long-term persistence, data exfiltration, and unauthorized lateral movement by adversaries within the enterprise network.

## Recommendation

* Deploy the correlation logic to link Suricata alert events (`logs-suricata.*`) with Elastic Defend network events (`logs-endpoint.events.network-*`) within the SIEM environment.
* Establish a baseline for legitimate network-initiating processes to tune out administrative tools like PDQ Inventory and other authorized management software.
* Prioritize alerts involving destination IPs with poor reputation scores or those exhibiting unexpected beaconing behavior.
* Use the correlated process metadata (command_line, user, and parent process context) to rapidly triage the host-side origin of suspicious network connections.
