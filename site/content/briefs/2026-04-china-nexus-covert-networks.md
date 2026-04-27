---
title: China-Nexus Cyber Actors Using Covert Networks of Compromised Devices
slug: 2026-04-china-nexus-covert-networks
description: China-nexus cyber actors are increasingly using large-scale networks of compromised devices, including SOHO routers and IoT devices, to obscure the origin of their attacks and conduct various malicious activities, from reconnaissance to data exfiltration.
date: "2026-04-23T11:22:42Z"
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

A joint advisory highlights a significant shift in tactics employed by China-nexus cyber actors. They are moving away from using individually procured infrastructure and instead leveraging large-scale, externally provisioned networks of compromised devices. These "covert networks" primarily consist of Small Office Home Office (SOHO) routers, Internet of Things (IoT) devices, and smart devices, but can include any vulnerable device that can be exploited at scale. These networks are used for…
