---
title: Disruption of Large IoT DDoS Botnets
slug: 2024-01-iot-ddos-disruption
description: Law enforcement has disrupted significant IoT botnets responsible for launching record-breaking distributed denial-of-service (DDoS) attacks, impacting the availability of targeted systems.
date: "2026-03-20T05:50:09Z"
severities:
  - high
tags:
  - iot
  - ddos
  - botnet
  - disruption
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ryo55p/authorities_disrupt_worlds_largest_iot_ddos/
  - https://www.justice.gov/usao-ak/pr/authorities-disrupt-worlds-largest-iot-ddos-botnets-responsible-record-breaking-attacks
rules:
  - title: Detect High Volume Outbound Network Traffic
    description: Detects unusually high outbound network traffic, which could indicate a DDoS attack or botnet activity originating from a host within the network.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
  - title: Detect Multiple Connections to the Same Destination
    description: Detects a host initiating a large number of connections to the same destination IP within a short period, which could be indicative of DDoS activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Authorities have dismantled a globally distributed network of compromised Internet of Things (IoT) devices that were being leveraged to conduct large-scale DDoS attacks. The botnets consisted of a large number of IoT devices. These attacks overwhelmed target systems, rendering them inaccessible. While the specific devices, malware, and attribution remain undisclosed in the provided source, the disruption of these botnets is a significant event for defenders, as it reduces the overall capacity…
