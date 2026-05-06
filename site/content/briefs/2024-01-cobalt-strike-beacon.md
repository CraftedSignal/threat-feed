---
title: Cobalt Strike Command and Control Beacon Detected
slug: 2024-01-cobalt-strike-beacon
description: This brief documents the detection of Cobalt Strike command and control activity through identifying specific domain naming conventions used by its implant beacons, indicative of network attack and exploitation campaigns.
date: "2024-01-09T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - FIN7
  - Carbon Spider
  - Sangria Tempest
tags:
  - command-and-control
  - cobalt-strike
  - domain-generation-algorithm
vendors:
  - Elastic
products:
  - packetbeat
  - auditbeat
  - filebeat
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568
    technique_name: Dynamic Resolution
references:
  - https://blog.morphisec.com/fin7-attacks-restaurant-industry
  - https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html
  - https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack
rules:
  - title: Cobalt Strike Domain Generation Algorithm Detection
    description: Detects Cobalt Strike C2 activity based on domain naming conventions commonly used by its beacons.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - network_connection
      - windows
  - title: Cobalt Strike HTTP Beaconing Detection
    description: Detects Cobalt Strike HTTP beaconing activity by identifying specific patterns in the HTTP request.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Cobalt Strike is a threat emulation platform that is often modified and used by adversaries, such as FIN7, to conduct network attack and exploitation campaigns. This rule detects network activity leveraged by Cobalt Strike implant beacons for command and control (C2). The detection focuses on a specific domain naming convention employed by Cobalt Strike beacons, allowing defenders to identify potentially compromised systems communicating with a C2 server. The observed pattern is `[a-z]{3}.stage.[0-9]{8}\..*`, which can be indicative of malicious C2 activity. This detection helps analysts pinpoint potential threats early in the attack lifecycle.

## Attack Chain

1.  Initial compromise of a system via unspecified means (e.g., phishing, exploitation).
2.  Deployment of a Cobalt Strike beacon on the compromised host.
3.  The beacon initiates network communication using HTTP or TLS protocols.
4.  The beacon attempts to resolve a domain matching the pattern `[a-z]{3}.stage.[0-9]{8}\..*`.
5.  DNS request is made to resolve the C2 server's IP address using the generated domain.
6.  The beacon establishes a connection to the C2 server using the resolved IP address.
7.  The compromised host receives commands and executes them.
8.  Exfiltration of sensitive data or further lateral movement within the network.

## Impact

Compromised systems can be used to exfiltrate sensitive data, deploy ransomware, or perform lateral movement to compromise other systems within the network. FIN7, a known threat actor, has been observed utilizing this technique, primarily targeting organizations for financial gain. Successful exploitation can lead to significant financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule `Cobalt Strike Domain Generation Algorithm Detection` to your SIEM to detect Cobalt Strike C2 activity based on domain naming conventions.
*   Review and tune the Sigma rule, excluding known legitimate systems or services using similar domain patterns, as described in the rule's `false_positives` section.
*   Enable network traffic logging (e.g., packetbeat, auditbeat, filebeat) to provide the data source required for the Sigma rule `Cobalt Strike Domain Generation Algorithm Detection`.
*   Block the C2 domain pattern `[a-z]{3}.stage.[0-9]{8}\..*` at the DNS resolver to prevent beacon resolution.
*   Investigate systems identified by this rule for signs of compromise, such as unusual processes or network connections, as described in the investigation guide.
