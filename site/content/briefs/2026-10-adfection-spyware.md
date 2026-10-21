---
brief_id: brief-2026-10-21-adfection-spyware
event_id: brief-2026-10-21-adfection-spyware
revision: 1
activity_at: "2026-10-21T07:58:02Z"
title: 'AdFection: Targeted mobile advertising exploited for zero-click spyware delivery'
slug: 2026-10-adfection-spyware
description: The AdFection campaign, facilitated by the ad-broker Discover-Tech and attributed to the mercenary vendor Candiru, delivers zero-click exploits via targeted mobile advertising to compromise iOS and Android devices.
date: "2026-10-21T07:58:02Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Candiru
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
tags:
  - mercenary-spyware
  - ad-fraud
  - mobile-threats
  - drive-by-download
vendors:
  - Candiru
products:
  - Integrity Labs Spyware
  - Discover-Tech (ad brokering services)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Researchers say that mercenary hackers laced ads with zero-click exploits that installed sophisticated malware on the devices of targeted individuals when they did nothing other than load a website or open an installed app.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: In response, those servers delivered an exploit that served the zero-click payload when the ad appeared on an individual’s device.
    confidence_band: high
references:
  - https://arstechnica.com/security/2026/10/targeted-ads-delivered-0-click-exploits-to-install-mercenary-malware/
  - https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy network-level ad blocking to prevent loading of ad exchange domains.
      owner: SOC
      due: 48h
      evidence: Citizen Lab researchers said users can reduce the risk of being infected by installing ad blockers.
  mitigation_plan:
    - priority: immediate
      action: Mandate OS and application updates on all mobile devices managed by the organization.
      owner: IT Operations
      addresses: Zero-click exploit delivery
      evidence: As always, installing updates in a timely manner is also a must.
---

Citizen Lab identified the AdFection campaign, which leverages a malicious advertising pipeline to deliver zero-click exploits to mobile devices. Discover-Tech, an ad-brokering firm, served as the distribution bridge, allowing mercenary spyware developers to bid on ad impressions targeting specific user demographics based on mobile IDs, location, and IP addresses. Once a targeted individual loaded a webpage or opened an app containing the malicious ad, the device executed code that connected to Candiru's (rebranded as Integrity Labs) command-and-control servers, resulting in a zero-click exploit delivery. The campaign was confirmed to have infected 45 devices at Al Jazeera between 2024 and 2025.

## Attack Chain

1. Profiling: Attackers assemble detailed user profiles using unique mobile IDs, location, and IP addresses.
2. Brokering: The malicious ad is placed into the legitimate advertising ecosystem via the Discover-Tech brokerage.
3. Delivery: The target loads a webpage or opens a mobile application that displays the malicious advertisement.
4. Execution: JavaScript or similar code within the advertisement executes upon rendering.
5. C2 Communication: The executing code initiates a connection to infrastructure controlled by Candiru (Integrity Labs).
6. Exploitation: The C2 infrastructure delivers a zero-click exploit payload to the target device, leading to full infection.

## Impact

Citizen Lab confirmed 45 infections at Al Jazeera between 2024 and 2025. The malware facilitates persistent spyware infection, enabling invisible monitoring of targeted journalists, government officials, and critical infrastructure personnel.

## Recommendation

- Implement network-level ad-blocking solutions across corporate and newsroom environments to disrupt the delivery of malicious ad creative.
- Enforce regular mobile operating system and application updates to mitigate the zero-click vulnerabilities leveraged in this campaign.
- Advise high-risk individuals to reset mobile advertising identifiers regularly and consider disabling personalized ad tracking at the OS level.
- Configure mobile device management (MDM) policies to restrict unnecessary application permissions and background data access.
