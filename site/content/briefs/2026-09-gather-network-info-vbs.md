---
title: Suspicious Reconnaissance Activity via GatherNetworkInfo.VBS
slug: 2026-09-gather-network-info-vbs
description: Adversaries are utilizing the native Windows script GatherNetworkInfo.vbs to perform system reconnaissance and collect network configuration data.
date: "2026-09-03T12:45:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - reconnaissance
  - discovery
  - lotl
  - living-off-the-land
  - windows-scripting
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1615
    technique_name: Group Policy Discovery
    evidence: The script gatherNetworkInfo.vbs gathers network and system information typically used for discovery.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: Visual Basic
    evidence: Detects execution of the built-in script located in C:\Windows\System32\gatherNetworkInfo.vbs.
    confidence_band: high
references:
  - https://posts.slayerlabs.com/living-off-the-land/#gathernetworkinfovbs
  - https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government
rules:
  - title: Detect Execution of GatherNetworkInfo.VBS
    description: Detects execution of the built-in Windows script gatherNetworkInfo.vbs, which is often used for system reconnaissance
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.005
      - T1615
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to production SIEM
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for process execution events involving gatherNetworkInfo.vbs not initiated by system administrative processes
      technique_id: T1059.005
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
---

GatherNetworkInfo.vbs is a legitimate, built-in Windows administrative script located in "C:\Windows\System32\" designed to assist in gathering system network information for troubleshooting purposes. Threat actors increasingly leverage this script as a Living-off-the-Land (LotL) technique to perform stealthy reconnaissance on compromised hosts. By executing this script, an attacker can obtain detailed network configuration, routing tables, and interface information without deploying additional malware. This technique is particularly effective for post-exploitation discovery, as the script is signed by Microsoft and exists in the baseline of many Windows installations. Defenders should monitor for unexpected execution of this script, especially when it is not initiated by standard system management tools or administrative workflows.

## Impact

Successful execution of this technique allows unauthorized actors to map internal network segments, identify active network interfaces, and collect sensitive configuration data that facilitates further lateral movement and privilege escalation. While no specific victim counts are reported, this method has been observed in campaigns targeting government infrastructure and enterprise environments.

## Recommendation

- Deploy the provided Sigma rule to detect non-standard execution of GatherNetworkInfo.vbs.
- Establish a baseline of legitimate administrative activity involving the Windows System32 directory to reduce false positives.
- Correlate execution events with parent process information to identify potential malicious actors or tools attempting to bypass standard script interpreters.
