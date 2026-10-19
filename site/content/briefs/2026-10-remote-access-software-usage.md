---
title: Detection of Unauthorized Remote Access Software Traffic
slug: 2026-10-remote-access-software-usage
description: Adversaries leverage legitimate remote access tools for command-and-control and persistence, requiring network monitoring to identify unauthorized usage of applications such as AnyDesk, TeamViewer, and LogMeIn.
date: "2026-10-19T13:56:52Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - command-and-control
  - network-monitoring
  - c2
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Adversaries often use remote access tools to maintain unauthorized access to compromised environments.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Implement network traffic monitoring for remote access software signatures using the Splunk ESCU analytic logic.
      owner: Detection Engineering
      due: 48h
      evidence: Source describes the need to monitor network traffic for T1219 to identify unauthorized access.
  hunt_leads:
    - lead: Identify all endpoints with outbound traffic to known remote access application gateways.
      technique_id: T1219
      data_needed:
        - Palo Alto Network Traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source advises that adversaries use these tools for persistence.
  mitigation_plan:
    - priority: medium_term
      action: Implement application control policies to restrict the execution of unauthorized remote access binaries on endpoints.
      owner: IT Operations
      addresses: T1219
      evidence: Restricting unauthorized RAS reduces the attack surface for C2.
  gaps:
    - Lack of visibility into encrypted traffic where application signatures are not decrypted at the perimeter.
---

Adversaries frequently employ legitimate remote access software (RAS) to maintain unauthorized access, facilitate lateral movement, and establish persistent command-and-control (C2) channels within compromised environments. This behavior, categorized under MITRE ATT&CK technique T1219 (Remote Access Software), allows attackers to bypass traditional security controls by masquerading malicious remote sessions as legitimate administrative or support traffic. 

Defenders should focus on identifying network traffic associated with common remote access applications such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer. This detection approach leverages Palo Alto network traffic logs mapped to the Splunk Network_Traffic data model. Because these tools are often dual-use, the efficacy of detection depends on baseline tuning to account for authorized internal usage. Monitoring these applications is critical for detecting Scattered Spider and various ransomware operations that rely on RMM tools to maintain persistent access after initial compromise.

## Impact

Successful deployment of unauthorized remote access tools enables attackers to maintain long-term persistence, exfiltrate sensitive data, and distribute ransomware payloads across the network. Organizations in sectors targeted by groups like Scattered Spider are particularly at risk. Failure to detect these tools allows attackers to retain control over endpoints even after initial delivery mechanisms are remediated, often leading to full-scale data encryption or credential theft.

## Recommendation

- Ingest Palo Alto network traffic logs into your SIEM and ensure normalization via the Common Information Model (CIM) to the Network_Traffic data model.
- Establish a baseline of legitimate remote access software usage within your environment to minimize false positives.
- Implement a lookup table of known remote access software signatures and update it regularly using resources like Applipedia.
- Use the provided Splunk analytic logic to monitor for outbound traffic matching the defined remote access software signatures.
- Configure the 'remote_software_exceptions' KVStore collection to track and maintain device-based exceptions for authorized tools.
