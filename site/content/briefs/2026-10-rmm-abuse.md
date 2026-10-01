---
title: Detection of RMM Software Execution from Commonly Abused Web Services
slug: 2026-10-rmm-abuse
description: Adversaries are actively abusing legitimate, digitally signed remote monitoring and management (RMM) software, often delivered via public cloud storage or file-sharing services, to maintain persistent command-and-control access in Windows environments.
date: "2026-10-01T14:09:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - remote-access
  - command-and-control
  - windows
  - rmm
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries use these services to deliver remote-access software during social engineering and intrusion campaigns.
    confidence_band: high
references:
  - https://www.huntress.com/blog/series-of-unfortunate-rmm-events
  - https://www.cloudflare.com/cloudforce-one/research/report/vercel-hosted-rmm-abuse-campaign-evolves-with-telegram-c2-for-victim-filtering/
  - https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review RMM tool usage in the environment and compare against authorized IT management software.
      owner: SOC
      due: 48h
  hunt_leads:
    - lead: Search for unsigned or rarely seen RMM binaries downloaded from domains like github.com, files.slack.com, or mega.nz.
      technique_id: T1219
      data_needed:
        - Process creation events with origin_url metadata
      priority: medium
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution of RMM tools via AppLocker or EDR policies to only allow approved administrative tools.
      owner: IT Operations
---

Threat actors frequently leverage legitimate remote monitoring and management (RMM) tools as a mechanism for persistent command-and-control (C2) access. By downloading these dual-use tools from public web services, cloud hosting platforms, or file-sharing sites, attackers bypass traditional perimeter filters. The observed behavior involves the execution of digitally signed binaries - such as those from ScreenConnect, TeamViewer, or AnyDesk - in scenarios inconsistent with established administrative or organizational deployment workflows. This technique is commonly employed during the post-exploitation phase of social engineering campaigns or broader intrusions to facilitate remote desktop control and exfiltration. Because these tools are often legitimate and signed by reputable publishers, defenders must prioritize context-aware detections that correlate the software's origin URL and execution path against known administrative baselines.

## Attack Chain

1. Attacker stages a legitimate, signed RMM installer on a public web service (e.g., GitHub, Dropbox, or S3 bucket).
2. The victim is lured to the malicious URL via a spear-phishing link or a compromised document.
3. The RMM binary is downloaded to the victim's host, often inheriting a "Zone.Identifier" alternate data stream indicating an internet origin.
4. The attacker executes the downloaded RMM binary, triggering a process start event.
5. The RMM tool establishes an outbound connection to the attacker's controller or the vendor's infrastructure for remote access.
6. The attacker uses the persistent remote desktop session to perform internal reconnaissance, credential theft, or data exfiltration.

## Impact

Successful abuse of RMM software grants attackers full interactive control over the host. If left undetected, this access allows for long-term persistence, lateral movement, and data theft. These campaigns have been observed across various sectors as attackers evolve their delivery methods to include victim filtering and trojanized installers.

## Recommendation

1. Deploy behavioral detection rules that correlate process execution with origin URL telemetry, specifically monitoring for RMM tools sourced from non-corporate domains.
2. Review the list of monitored RMM publishers identified in the detection logic and validate them against internal IT administrative tools.
3. Implement strict egress filtering to restrict unauthorized remote access tools from reaching known C2 infrastructure or non-essential external endpoints.
4. Investigate any process execution of software signed by the publishers listed in the detection criteria that does not align with authorized software distribution or support tickets.
