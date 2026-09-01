---
title: Detection of Non-Standard Network Port Usage via PowerShell
slug: 2026-09-uncommon-port-testing
description: This brief documents a detection capability for identifying potential command-and-control activity where adversaries use PowerShell to test network connectivity over non-standard, uncommon ports.
date: "2026-09-01T12:18:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - t1571
  - windows
  - powershell
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
    evidence: Adversaries may communicate using a protocol and port paring that are typically not associated.
    confidence_band: high
rules:
  - title: Detect Use of Test-NetConnection with Uncommon Ports
    description: Detects the use of Test-NetConnection to query ports other than standard HTTP/HTTPS (80/443), which may indicate reconnaissance for C2 setup.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1571
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script parameters.
    - action: Deploy the Sigma detection rule to the production SIEM.
      owner: Detection Engineering
      due: 72h
      evidence: Provides visibility into reconnaissance activity.
  mitigation_plan:
    - priority: medium_term
      action: Enforce network egress filtering to prevent unauthorized connections to non-standard ports.
      owner: Network Security
      addresses: T1571
      evidence: Limits the ability of C2 channels to egress the network.
---

Adversaries frequently employ techniques to evade network monitoring by utilizing protocols and port pairings that are not traditionally associated with specific traffic types. By establishing command-and-control (C2) channels over non-standard ports, such as 8088 or 587, attackers attempt to blend in with authorized traffic and bypass static firewall rules or simple inspection policies. The PowerShell cmdlet `Test-NetConnection` is often misused by attackers during the post-exploitation reconnaissance phase to verify reachability and ensure that a target host can communicate with external C2 infrastructure over these unconventional ports. This brief focuses on the detection of such reconnaissance activity using PowerShell Script Block Logging, which provides visibility into the parameters passed to network diagnostic commands.

## Impact

Successful exploitation of non-standard port communication allows attackers to maintain persistent, covert C2 channels, potentially leading to unauthorized data exfiltration, lateral movement, or long-term remote administration of compromised endpoints. Detecting this activity early in the network reconnaissance phase is critical to preventing the establishment of a stable C2 infrastructure and mitigating further compromise within the target environment.

## Recommendation

Detection engineering teams should focus on identifying suspicious usage of network connectivity tools in scripting environments. 

- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the command-line arguments used in administrative tools.
- Deploy the Sigma rule provided below to the SIEM and tune the filter list to exclude known administrative or monitoring tools specific to the local network environment.
- Monitor logs for instances of `Test-NetConnection` where the destination port does not align with standardized port assignments (e.g., ports other than 80, 443).
