---
title: Detection of Port Proxy Registry Modifications for Protocol Tunneling
slug: 2026-10-windows-portproxy-registry
description: Adversaries manipulate the Windows PortProxy registry keys to establish unauthorized port forwarding, enabling lateral movement and the bypassing of network segmentation.
date: "2026-10-07T16:40:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - defense-evasion
  - registry-modification
  - windows
  - port-forwarding
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: An adversary may abuse this technique to bypass network segmentation restrictions.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: This rule monitors the modifications to the HKLM\SYSTEM\*ControlSet*\Services\PortProxy\v4tov4\ subkeys.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: This rule monitors the modifications to the HKLM\SYSTEM\*ControlSet*\Services\PortProxy\v4tov4\ subkeys.
    confidence_band: high
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/bypassing-network-restrictions-through-rdp-tunneling
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_port_forwarding_added_registry.toml
rules:
  - title: Detect Port Forwarding Rule Addition in Registry
    description: Detects the creation or modification of Windows Registry keys associated with the PortProxy service, often used to bypass network segmentation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1090.001
      - T1112
      - T1572
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy PortProxy registry modification detection rule.
      owner: Detection Engineering
      due: 48h
      evidence: Addresses identified TTPs for persistence and C2.
  hunt_leads:
    - lead: Search for existing registry keys under PortProxy for unauthorized redirection.
      technique_id: T1112
      data_needed:
        - Registry change logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries leverage this native Windows functionality to establish port forwarding.
  mitigation_plan:
    - priority: short_term
      action: Remove unauthorized PortProxy rules.
      owner: IT Operations
      addresses: T1090.001
      evidence: Delete the port forwarding rule.
---

Windows PortProxy is a native component of the IPv6 transition technology that allows for the redirection of TCP traffic between IPv4 and IPv6 addresses, or to different ports on the same or remote machines. Threat actors abuse this functionality by modifying registry keys under `HKLM\SYSTEM\*ControlSet*\Services\PortProxy\v4tov4\` to create persistent or temporary port forwarding rules. This technique is often employed as a post-compromise activity to facilitate internal proxying, tunnel malicious traffic, or act as a jump box to traverse network segmentation restrictions. Monitoring these specific registry keys is essential for detecting unauthorized persistence and hidden Command and Control (C2) communication channels. Defenders should focus on process execution context surrounding these registry modifications to identify suspicious administrative activity.

## Impact

Successful exploitation allows attackers to bypass network perimeter defenses and segmentation. This enables lateral movement into isolated network segments, redirection of internal traffic to external C2 infrastructure, and the ability to maintain communication channels that may evade traditional network-based security controls.

## Recommendation

Prioritize detection and investigation of registry modifications targeting PortProxy configurations.

* Deploy the provided Sigma rule to monitor registry changes under `HKLM\SYSTEM\*ControlSet*\Services\PortProxy\v4tov4\`.
* Investigate the parent process of any modification to these keys to identify unauthorized administrative activity.
* Audit existing PortProxy rules during incident response to identify and remove unauthorized tunnels used as backdoors.
* Enable Sysmon registry event logging (Event ID 12 or 13) to capture these modifications.
