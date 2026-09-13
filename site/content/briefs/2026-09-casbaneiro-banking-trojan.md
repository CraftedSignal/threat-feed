---
title: Casbaneiro Banking Trojan Campaign in Latin America
slug: 2026-09-casbaneiro-banking-trojan
description: A Casbaneiro banking trojan campaign is actively targeting Latin American users by leveraging geofencing and distributed infrastructure to hinder analysis and detection.
date: "2026-09-13T22:15:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - banking-trojan
  - financial-fraud
  - latin-america
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1480
    technique_name: Execution Guardrails
    evidence: The malware employs advanced evasion techniques, including geofencing to restrict activity to specific regions.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The malware utilizes a distributed infrastructure of data-receiving servers to complicate analysis.
    confidence_band: high
references:
  - https://feeds.fortinet.com/~/968920310/0/fortinet/blog/threat-research~Casbaneiro-A-Banking-Trojan-with-Distributed-DataReceiving-Servers
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  enrichment_needed:
    - item: C2 server infrastructure
      owner: CTI
      reason: Distributed nature of servers requires dynamic intelligence updates
      evidence: Source notes distributed data-receiving servers
  hunt_leads:
    - lead: Anomalous process injection into browser processes
      technique_id: T1055
      data_needed:
        - Process injection events (Sysmon ID 8)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Common behavior for Casbaneiro banking trojan class
---

FortiGuard Labs identified a recent campaign involving the Casbaneiro banking trojan, which focuses on financial theft targeting victims in Latin America. This iteration of the malware distinguishes itself through sophisticated evasion tactics designed to thwart security researchers and automated defensive systems. The operators utilize geofencing to ensure the malicious payload remains dormant or executes differently when accessed from outside their target geographic scope. Furthermore, the threat actor employs a distributed network of data-receiving servers for command-and-control (C2) and exfiltration, making it difficult for security operations centers (SOCs) to block communications via simple IP or domain filtering. This campaign demonstrates a continued evolution in Latin American-focused financial malware, requiring defenders to move beyond perimeter-based controls toward behavior-based endpoint and network monitoring.

## Impact

The campaign poses a significant risk to individuals and organizations within Latin America, aiming primarily at the theft of banking credentials and financial data. The use of distributed infrastructure increases the likelihood of successful data exfiltration by complicating threat intelligence attribution and blocking efforts. Organizations in the financial sector or those with regional operations in Latin America are at an elevated risk of financial loss and account compromise.

## Recommendation

Prioritize the implementation of advanced endpoint detection to identify anomalous behaviors associated with banking trojans, as infrastructure-based blocking (IPs/domains) is likely to be ineffective due to the distributed nature of the servers. Monitor for suspicious inter-process communication and unauthorized attempts to hook browser processes, which are common indicators of Casbaneiro's activity. Ensure that regional security policies account for the specific threat profile of banking trojans targeting local financial institutions.
