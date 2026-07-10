---
title: Keitaro Tracker Abused in AI-Driven Investment Scams
slug: 2024-01-30-keitaro-abuse
description: The Keitaro Tracker advertising platform is being exploited by malicious actors to facilitate AI-driven investment scams.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - keitaro
  - tds
  - traffic-direction
  - investment-scam
  - ai
vendors:
  - Keitaro
products:
  - Keitaro Tracker
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rynl1o/inside_keitaro_abuse_a_persistent_stream_of/
  - https://www.infoblox.com/blog/threat-intelligence/inside-keitaro-abuse-a-persistent-stream-of-ai-driven-investment-scams/
iocs:
  - type: domain
    value: infoblox.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Network Connection to Infoblox Domain
    description: Detects network connections to the Infoblox domain, potentially indicating reconnaissance activity or attempts to access threat intelligence resources.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1589
    data_sources:
      - network_connection
      - windows
  - title: Detect Outbound Connections to Uncommon Ports
    description: Detects processes making outbound connections to uncommon ports, potentially indicating C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Keitaro Tracker, sometimes referred to as Keitaro TDS, is an advertising performance tracking platform that has been observed being abused in malicious campaigns. Threat actors are leveraging this platform to facilitate and track AI-driven investment scams. The specific details of the scams and the threat actors behind them are not available in the provided source. However, the core issue is the abuse of a legitimate advertising tool for illicit purposes. This matters to defenders because it highlights the need to monitor not just known malicious infrastructure but also the potential misuse of common advertising and tracking platforms.

## Attack Chain

Given the limited information, a generic attack chain based on typical Keitaro abuse is outlined:

1.  **Initial Advertisement:** Threat actors create advertisements promoting investment opportunities, often leveraging AI buzzwords.
2.  **User Clicks Ad:** Unsuspecting users click on the advertisements, which are often displayed on compromised websites or through malvertising campaigns.
3.  **Keitaro Redirection:** Keitaro Tracker is used to track the click and redirect the user based on various parameters (geolocation, device type, etc.) to a landing page.
4.  **Landing Page:** The landing page presents a seemingly legitimate investment platform or opportunity.
5.  **Data Collection:** The user is prompted to enter personal and financial information on the landing page, which is then collected by the attackers.
6.  **Investment Scam:** The collected information is used to perpetrate investment scams, such as fake trading platforms or Ponzi schemes.
7.  **Financial Loss:** Victims are persuaded to invest funds, which are then stolen by the attackers.

## Impact

The abuse of Keitaro Tracker in AI-driven investment scams can lead to significant financial losses for victims. The scale of these campaigns is unknown, but the potential for widespread impact is high due to the broad reach of online advertising networks. Victims may also suffer emotional distress and identity theft as a result of providing personal information to the attackers. The reputational damage to legitimate advertising platforms is also a concern.

## Recommendation

*   Monitor network traffic for connections to known Keitaro Tracker instances and investigate unusual redirection patterns.
*   Implement web filtering to block access to known malicious landing pages associated with investment scams.
*   Educate users about the risks of online investment scams and the importance of verifying the legitimacy of investment platforms before providing personal information.
*   Enable DNS query logging and deploy the rule below to detect potential domain generation algorithms used by Keitaro.
*   Investigate processes making outbound connections to uncommon ports to identify potential C2 activity.
