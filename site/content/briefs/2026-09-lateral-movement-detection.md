---
title: Detection of Potential Lateral Movement via Alert Correlation
slug: 2026-09-lateral-movement-detection
description: This detection capability monitors for lateral movement by identifying sequences where a host IP address from one security alert subsequently appears as the source IP in alerts from a different host.
date: "2026-09-18T19:19:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - threat-detection
  - esql
  - detection-engineering
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: The rule identifies potential lateral movement or post-compromise activity by correlating alerts where the host.ip of one alert matches the source.ip of a subsequent alert.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable host.ip collection on all endpoints in the environment.
      owner: IT Operations
      due: 48h
      evidence: The rule requires the host.ip field to be populated.
  hunt_leads:
    - lead: Identify pairs of hosts with high-frequency alert cross-correlation.
      technique_id: T1021
      data_needed:
        - Security alert logs containing source.ip and host.ip
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The rule identifies cross-host alert sequences.
---

This detection rule provides a higher-order analytical approach to identify lateral movement by correlating disparate security alerts across an enterprise network. Instead of focusing on single atomic events, the rule logic aggregates alerts where the `host.ip` of one host correlates with the `source.ip` of alerts originating from a separate host. This pattern suggests an adversary is using a compromised endpoint as a pivot point to conduct further reconnaissance or access additional systems within the environment. The rule filters out low-severity events and specific noise-prone alerts to maintain a high signal-to-noise ratio, effectively acting as an automated threat hunting mechanism to surface cross-host infection chains.

## Impact

Successful lateral movement allows adversaries to navigate an internal network, elevate privileges, and reach high-value assets such as domain controllers, sensitive file shares, or cloud service configuration interfaces. If left undetected, this phase of an attack often precedes ransomware deployment, large-scale data exfiltration, or long-term persistence in the target network.

## Recommendation

Prioritized actions for detection and response teams:
- Deploy the higher-order detection logic to identify cross-host alert correlation patterns indicating potential pivots.
- Enable `host.ip` collection for all endpoints, specifically ensuring Elastic Defend versions 8.18 and above are configured to populate this field as required for the logic.
- Review the list of triggered alerts to isolate the patient-zero host; perform network isolation immediately upon confirming lateral movement indicators.
- Investigate the specific user accounts associated with the source and destination alerts to determine if credentials were compromised or if non-interactive service accounts are being abused.
- Tune the detection logic to account for known network architecture artifacts, such as NAT gateways, proxies, or jump hosts, which may generate frequent cross-host alert patterns.
