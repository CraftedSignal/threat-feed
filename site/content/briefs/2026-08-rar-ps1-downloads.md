---
title: Adversary Use of RAR and PowerShell Downloads for Tooling Delivery
slug: 2026-08-rar-ps1-downloads
description: Adversaries, including FIN7, utilize the downloading of RAR archives and PowerShell scripts from external sources to retrieve encoded or encrypted payloads to facilitate initial access and lateral movement.
date: "2026-08-31T07:04:49Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - command-and-control
  - ingress-tool-transfer
  - fin7
  - network-security
vendors:
  - Palo Alto Networks
  - Fortinet
products:
  - PAN-OS
  - FortiGate
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Gaining initial access to a system and then downloading encoded or encrypted tools to move laterally is a common practice for adversaries.
    confidence_band: high
references:
  - https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html
  - https://www.justice.gov/opa/press-release/file/1084361/download
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
rules:
  - title: Detect Suspicious RAR or PowerShell File Download
    description: Detects internal hosts downloading .rar or .ps1 files from the internet, a common TTP used for ingress tool transfer.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - network_traffic
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy network detection rule for .rar and .ps1 downloads.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides query logic and rule metadata.
  hunt_leads:
    - lead: Identify historical external downloads of .rar or .ps1 files.
      technique_id: T1105
      data_needed:
        - Network logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Rule documentation indicates this is a common adversary practice.
  mitigation_plan:
    - priority: short_term
      action: Enforce network segmentation.
      owner: IT Operations
      addresses: T1105
      evidence: Mitigation step recommended in rule guide.
---

Adversaries, notably the FIN7 group, frequently employ the technique of downloading secondary payloads via RAR archives or PowerShell scripts from the internet to evade detection. By leveraging these formats, attackers can obfuscate or encrypt their command-and-control (C2) tools, preventing security appliances from performing immediate payload inspection. This activity often occurs following initial system access, as the downloaded tools are used to expand the adversary's footprint, conduct further reconnaissance, or facilitate lateral movement within the target environment. Because these file types are frequently used in administrative or update workflows, defenders must tune detection logic to distinguish between legitimate software management traffic and unauthorized ingress tool transfer.

## Attack Chain

1. Attacker gains initial access to an internal workstation or server via spearphishing or exploit.
2. Attacker initiates an outbound connection to an adversary-controlled server on the internet.
3. Attacker triggers a request for a malicious RAR archive or a PowerShell script (`.ps1`).
4. The internal host downloads the payload through the enterprise network gateway or firewall.
5. The file is extracted or executed by the attacker using native utilities (e.g., PowerShell or `rar.exe`).
6. The secondary payload establishes a C2 channel or deploys additional modules (e.g., infostealers, backdoors).
7. Attacker proceeds to conduct lateral movement or data exfiltration from the compromised host.

## Impact

Successful execution of this technique allows adversaries to bypass traditional perimeter security controls and deliver specialized malware. The impact includes unauthorized access to sensitive internal systems, credential harvesting, lateral movement across the network, and potential data exfiltration. Observed campaigns linked to FIN7 demonstrate the strategic use of such methods to maintain persistence and minimize the visibility of their malicious toolset within target environments.

## Recommendation

Prioritize the implementation of network-based monitoring for unusual file downloads and restrict ingress of suspicious file types to authorized hosts.

- Deploy the provided detection logic to correlate HTTP/TLS traffic with specific file extensions (.rar, .ps1).
- Configure network-based detection to alert on connections to external IP addresses that lack a legitimate business justification.
- Establish a process to white-list IP addresses of known internal software update servers and security tool distribution endpoints to reduce false positives.
- Conduct regular hunts for outbound requests from workstations to uncommon external IP ranges, specifically looking for attempts to fetch scripts or compressed archives.
- Enhance visibility by ensuring network traffic logs from firewalls (Palo Alto, Fortinet) are effectively ingested into the SIEM and mapped against established internal network segments.
