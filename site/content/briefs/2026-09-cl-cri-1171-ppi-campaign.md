---
title: CL-CRI-1171 Pay-Per-Install Infrastructure and Malware Campaign
slug: 2026-09-cl-cri-1171-ppi-campaign
description: The CL-CRI-1171 threat actor operates a large-scale pay-per-install marketplace, leveraging SEO poisoning and YouTube gaming lures to deploy a persistent multi-payload loader used to distribute malware including Insomnia RAT and ARKTunnel.
date: "2026-09-09T12:46:11Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - CL-CRI-1171
tags:
  - ppi
  - malware
  - seo-poisoning
  - loader
  - remote-access-trojan
  - c2
products:
  - WinDirStat (trojanized versions)
affected_os:
  - Windows 10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The SEO poisoning path was the first delivery channel we identified.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Content in the channels included advice on improving frame rates... but served as the delivery vehicle... prompting viewers to download malicious tools.
    confidence_band: high
references:
  - https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
iocs:
  - type: domain
    value: bubbleslip.xyz
  - type: domain
    value: churchpail.xyz
  - type: domain
    value: dinosaursjam.xyz
  - type: domain
    value: noiseship.cfd
  - type: domain
    value: atthelake.info
ioc_counts:
  domain: 5
rules:
  - title: Detect Suspicious PowerShell Staging for Insomnia RAT
    description: Detects PowerShell execution patterns consistent with the Insomnia RAT loader using a staging URL.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
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
    - action: Block listed IOC domains at egress firewall/DNS.
      owner: SOC
      due: 24h
      evidence: Source identified infrastructure as primary C2/delivery domains.
  enrichment_needed:
    - item: Rotational domain pattern analysis
      owner: CTI
      reason: Identify new domains based on the two-word compound naming pattern observed by Unit 42.
      evidence: Sprawling network of rotational domains following a two-word naming pattern.
  hunt_leads:
    - lead: Search logs for file execution of unknown installers from web-proxy traffic to .xyz, .cfd, .space, and .info domains.
      technique_id: T1204.002
      data_needed:
        - Proxy/Firewall logs
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Usage of specific TLDs for rotational malware distribution.
  mitigation_plan:
    - priority: immediate
      action: Enforce strict application control policies preventing execution of unsigned binaries or binaries in user-writable directories like C:\Users\Public\.
      owner: IT Operations
      addresses: Generic malware droppers
      evidence: Installation location observed in analysis.
  gaps:
    - Detection of the gate evasion mechanism remains difficult without specific client-side telemetry.
---

CL-CRI-1171 is a cybercrime group operating a pay-per-install (PPI) marketplace that facilitates the distribution of diverse malware payloads to enterprise and home networks. The group has been active since at least 2024, utilizing a shared loader infrastructure to deploy various secondary payloads, including the previously unreported Docro Hijacker, ARKTunnel, and the Insomnia RAT. The delivery infrastructure is highly evasive, employing a gate mechanism that fingerprints potential victims using parameters like operating system, browser, and referring URL. Requests that do not match expected criteria are served decoys, effectively blinding automated security scanners and analysts. This infrastructure facilitates the rotational deployment of unrelated malware families, ensuring the operator can monetize access to thousands of compromised endpoints, ranging from consumer gaming PCs to government and critical infrastructure workstations. The campaign is notable for its use of SEO poisoning and high-follower YouTube gaming channels, which provide a consistent stream of human traffic to the malicious delivery funnels.

## Attack Chain

1. Attacker establishes a funnel via YouTube gaming channels and SEO-poisoned pages for legitimate software like WinDirStat or Bluetooth drivers.
2. Victim navigates to a malicious landing page, triggering a fake virus-scan animation to build credibility.
3. The landing page gate performs client-side fingerprinting and validates the victim environment via a click_id parameter.
4. Upon validation, the gate serves a generic, trojanized installer (the OfferLoader) to the victim.
5. The installer executes and reaches out to rotational C2 domains to fetch additional payloads.
6. The loader drops secondary stage agents, such as PowerShell scripts or DLLs, designed to facilitate further persistence and download multi-stage agents (Node.js/Python).
7. Final stage payloads (e.g., Insomnia RAT, ARKTunnel) initiate C2 communication to exfiltrate data or establish remote access.

## Impact

The campaign has resulted in at least 10,000 distinct loader deployments, affecting organizations across government and critical infrastructure sectors. Successful infections provide unauthorized remote access and the ability to deploy arbitrary additional malware, leading to potential data exfiltration, long-term persistence, and the sale of access to other malicious actors via the PPI marketplace.

## Recommendation

* Deploy the provided detection rules to identify suspicious process execution chains associated with generic installers and PowerShell-based staging.
* Implement egress filtering to block the rotational C2 domain patterns and known bad domains identified in this brief at the DNS level.
* Monitor for unsigned or inconsistently signed installers masquerading as legitimate utilities like WinDirStat, particularly those originating from non-official domains.
* Investigate endpoints for the presence of PowerShell scripts downloading from external non-reputable domains, focusing on the file patterns identified in the technical analysis.
