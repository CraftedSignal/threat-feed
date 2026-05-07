---
title: Threat Activity Enablers (TAEs) Facilitating Cybercrime
slug: 2024-01-threat-activity-enablers
description: Threat Activity Enablers (TAEs) are infrastructure providers and networks that support malicious cyber activity, including ransomware, botnets, and state-sponsored operations, by providing resilient and obfuscated infrastructure.
date: "2026-05-06T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - threat-infrastructure
  - cybercrime
  - hosting-provider
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.recordedfuture.com/blog/threat-activity-enablers
rules:
  - title: Detect Rapid IP Address Prefix Transfers
    description: Detects rapid transfers of IP address prefixes, a tactic used by TAEs to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Connections to High Threat Density Networks
    description: Detects network connections to IP addresses within networks identified as having a high threat density score, indicating potential TAE activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Threat Activity Enablers (TAEs) are the often-overlooked backbone of modern cyber threats. These entities provide the infrastructure and services that enable threat actors to conduct malicious activities such as ransomware attacks, botnet operations, and infostealer campaigns. TAEs distinguish themselves from legitimate hosting providers by selectively responding to abuse reports, openly ignoring oversight, or advertising non-cooperation, maintaining plausible deniability while supporting criminal operations. They sustain operations by providing resilient, high-risk infrastructure that persists despite sanctions, takedowns, and public exposure. TAEs use various tactics to obfuscate their activities, including corporate shell games, strategic resource control (operating as local internet registries), and rapid rebranding to evade accountability.

## Attack Chain

1.  TAEs establish front companies across multiple jurisdictions to create legal distance between the infrastructure and the operators (Corporate Shell Games).
2.  TAEs operate as local internet registries (LIRs) to gain direct control over IP resources and autonomous systems (ASNs) (Strategic Resource Control).
3.  Threat actors lease or rent infrastructure from TAEs.
4.  Threat actors deploy malware, command-and-control servers, or other malicious infrastructure on the TAE-provided resources.
5.  TAEs selectively respond to abuse reports or law enforcement inquiries to maintain plausible deniability.
6.  When a network becomes too "hot" due to scrutiny, TAEs rapidly transfer IP address prefixes to a newly registered, clean-looking entity (Rapid Rebranding).
7.  Threat actors use this infrastructure to launch attacks, conduct botnet operations, or facilitate other malicious activities.
8.  TAEs continue to support malicious activity, ensuring the persistence of the threat infrastructure.

## Impact

TAEs enable a wide range of malicious activities, including ransomware attacks, infostealer campaigns, botnets, and state-sponsored operations. The persistent nature of TAE-supported infrastructure allows threat actors to maintain a sustained presence and launch attacks with greater impunity. By providing a safe haven for malicious infrastructure, TAEs amplify the impact of cyber threats, making it more difficult for security teams to defend against them.

## Recommendation

*   Monitor network traffic for connections to IP ranges and ASNs associated with known TAEs, identified via the Network Threat Density List (prevention).
*   Implement detections for rapid IP address prefix transfers, which are indicative of TAE rebranding activities (detection).
*   Prioritize investigation of alerts originating from networks with high Threat Density Scores (detection).
*   Utilize threat intelligence feeds that incorporate TAE data to enrich security monitoring and incident response efforts (prevention, detection, exposure).
