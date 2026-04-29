---
title: China-Nexus Cyber Actors Using Covert Networks of Compromised Devices
slug: 2026-04-china-nexus-covert-networks
description: China-nexus cyber actors are increasingly using large-scale networks of compromised devices, including SOHO routers and IoT devices, to obscure the origin of their attacks and conduct various malicious activities, from reconnaissance to data exfiltration.
date: "2026-04-23T11:22:42Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - China-nexus cyber actors
tags:
  - covert-network
  - botnet
  - china-nexus
  - compromised-devices
vendors:
  - Cisco
  - Netgear
products:
  - SOHO Routers
  - IoT Devices
  - Web Cameras
  - Video Recorders
  - Firewalls
  - Network Attached Storage (NAS) Devices
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-113a
  - https://www.ncsc.gov.uk/news/defending-against-china-nexus-covert-networks-of-compromised-devices
rules:
  - title: Detect Outbound Connection to Known SOHO Devices
    description: Detects outbound connections from internal network to public IP addresses commonly associated with SOHO routers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Scanning Activity from Internal Hosts
    description: Detects potential network scanning activity originating from internal hosts, indicative of compromised devices performing reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A joint advisory highlights a significant shift in tactics employed by China-nexus cyber actors. They are moving away from using individually procured infrastructure and instead leveraging large-scale, externally provisioned networks of compromised devices. These "covert networks" primarily consist of Small Office Home Office (SOHO) routers, Internet of Things (IoT) devices, and smart devices, but can include any vulnerable device that can be exploited at scale. These networks are used for various purposes, including disguising the origin of malicious activity, scanning networks, delivering malware, communicating with compromised systems, exfiltrating stolen data, and conducting general deniable internet browsing to research new TTPs and victim profiles. These networks are constantly updated and could be used by multiple actors.

## Attack Chain

1.  Initial Compromise: China-nexus actors exploit vulnerabilities in SOHO routers, IoT devices (web cameras, video recorders), firewalls, and NAS devices.
2.  Botnet Establishment: Compromised devices are incorporated into a covert network (botnet), often controlled by Chinese information security companies.
3.  Reconnaissance: The actors use the botnet to scan target networks, gathering information about potential vulnerabilities and attack surfaces.
4.  Exploitation: Leveraging the compromised network to mask their origin, the actors exploit identified vulnerabilities in target systems.
5.  Malware Delivery: The covert network is used to deliver malware payloads to compromised systems within the target network.
6.  Command and Control: The actors establish command and control (C2) channels through the compromised network to remotely control the malware and maintain access.
7.  Data Exfiltration: Sensitive data is exfiltrated from the compromised network through the covert network, making attribution difficult.
8.  Persistence: The actors maintain persistence on compromised systems to ensure continued access and control.

## Impact

Compromised networks can lead to the exposure of sensitive data, disruption of critical services, and financial losses. The use of covert networks makes attribution difficult, allowing attackers to operate with impunity. The advisory notes that Volt Typhoon has used these techniques to pre-position on critical national infrastructure. The widespread nature of the networks, comprising potentially hundreds of thousands of endpoints, makes traditional network defense strategies like static IP blocklists less effective. In 2024, one such network, Raptor Train, infected over 200,000 devices worldwide.

## Recommendation

*   Implement robust patch management practices to keep SOHO routers, IoT devices, and other network devices up-to-date with the latest security patches (reference: Overview).
*   Strengthen network perimeter security by implementing intrusion detection and prevention systems (IDPS) to identify and block malicious traffic originating from suspicious or known compromised IP addresses (reference: Attack Chain).
*   Monitor network traffic for unusual patterns and anomalies that may indicate the presence of a compromised device or covert network activity (reference: Attack Chain).
*   Deploy the Sigma rule "Detect Outbound Connection to Known SOHO Devices" to identify potential compromised devices on your network (reference: rules).
*   Segment networks to limit the potential impact of a compromised device or network segment (reference: Protective Advice).
