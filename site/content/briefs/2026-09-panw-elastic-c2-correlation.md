---
title: Correlation of Palo Alto Networks C2 Alerts with Endpoint Process Activity
slug: 2026-09-panw-elastic-c2-correlation
description: This detection capability correlates Palo Alto Networks (PANW) firewall command and control alerts with Elastic Defend endpoint events to identify the specific process responsible for network traffic flagged as malicious.
date: "2026-09-18T19:05:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - detection-engineering
  - network-security
  - cross-platform
vendors:
  - Palo Alto Networks
  - Elastic
products:
  - PAN-OS
  - Elastic Defend
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This detection correlates Palo Alto Networks (PANW) command and control events with Elastic Defend network events to identify the source process performing the network activity.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/command_and_control_pan_elastic_defend_c2.toml
  - https://attack.mitre.org/tactics/TA0011/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy correlation rule for PANW and Elastic Defend network events.
      owner: Detection Engineering
      due: 72h
      evidence: Correlation logic requires both PANW C2 events and endpoint connection logs.
  hunt_leads:
    - lead: Search for processes matching both firewall C2 flags and local network connection attempts.
      technique_id: T1071
      data_needed:
        - PAN-OS network logs
        - Elastic Defend endpoint logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source provides explicit EQL logic for this hunt.
---

This detection rule provides an integrated approach to identifying Command and Control (C2) activity by correlating network security logs from Palo Alto Networks (PANW) firewalls with host-level network telemetry from Elastic Defend. By matching network flows based on source IP, source port, and destination IP within a one-minute window, security teams can attribute network-level alerts to specific processes running on endpoints. This is critical for security operations as it bridges the gap between opaque perimeter firewall alerts and the actionable endpoint context required for incident response. The detection works across Windows, Linux, and macOS environments, enabling defenders to identify the parent process, command-line arguments, and historical behavior of binaries engaged in suspicious outbound communication.

## Impact

Successful exploitation or persistence by threat actors often involves C2 communication. If this activity is not attributed to a specific process, defenders may be unable to identify the source of the infection or perform effective remediation. This correlation method minimizes response time by providing the necessary process-level details to terminate malicious activity and isolate compromised systems, thereby reducing the risk of unauthorized data exfiltration or lateral movement.

## Recommendation

- Deploy the correlation logic to your SIEM to monitor for network flows identified as C2 by PANW that coincide with endpoint connection attempts.
- Prioritize investigation of processes identified by the correlation, focusing on command-line parameters and process reputation.
- Implement blocking rules on your firewall for the destination IPs flagged as C2 in these correlation events.
- Use the endpoint telemetry to review all network connections performed by the identified process within the 48 hours prior to the detection.
