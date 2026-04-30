---
title: Impact of Poor Security Operation Center (SOC) Metrics
slug: 2024-01-02-soc-metrics
description: Poorly chosen performance metrics can significantly impair a SOC's ability to detect and respond to threats, leading to ineffective security operations and potential compromise.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - soc
  - metrics
  - threat-hunting
  - detection
products:
  - SharePoint
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
references:
  - https://www.ncsc.gov.uk/blogs/could-your-choice-of-metrics-be-harming-your-soc
rules:
  - title: Detect Password Searches in SharePoint
    description: Detects attempts to locate passwords within SharePoint, which can be an indicator of reconnaissance or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
  - title: Excessive HTTP 404 Errors from Single Source IP
    description: Detects potential scanning activity by identifying a high volume of 404 errors originating from a single IP address.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The National Cyber Security Centre (NCSC) blog post highlights the detrimental effects of using inappropriate metrics to evaluate SOC performance. Focusing on easily quantifiable metrics like 'number of tickets processed', 'time taken to close a ticket', 'number of detection rules written', and 'volume of logs collected' can incentivize analysts to prioritize metric optimization over effective threat detection. These perverse incentives can lead to a high number of false positives, alert fatigue, and a failure to identify genuine security incidents. The blog emphasizes the importance of focusing on metrics that truly reflect a SOC's efficacy in detecting and responding to attacks in a timely manner, using red and purple teaming to simulate attacks.

## Attack Chain

This attack chain describes how an attacker might evade detection in a SOC environment using ineffective metrics.

1.  **Initial Foothold:** An attacker gains initial access via a vulnerability or credential compromise. This is not directly measured by common SOC metrics.
2.  **Internal Reconnaissance:** The attacker performs internal reconnaissance, such as `searching for passwords in a SharePoint`.
3.  **Lateral Movement:** The attacker uses discovered credentials to move laterally within the network.
4.  **Data Access:** The attacker accesses sensitive data, potentially including intellectual property or personal information.
5.  **Exfiltration Preparation:** The attacker prepares the data for exfiltration, such as compressing or encrypting it.
6.  **Exfiltration:** The attacker exfiltrates the data to an external server.
7.  **Persistence:** The attacker establishes persistence mechanisms to maintain access for future operations.
8.  **Impact:** The attacker achieves their objective, which could be data theft, system disruption, or financial gain. The lack of focus on TTD/TTR means the breach goes unnoticed until significant damage is done.

## Impact

The use of poor metrics can lead to a significant increase in dwell time, allowing attackers more time to achieve their objectives. Organizations may experience data breaches, financial losses, reputational damage, and regulatory fines. The NCSC observed SOCs with great potential rendered entirely ineffective through poor choice and application of metrics. If "time to close a ticket" is prioritized, analysts may quickly dismiss alerts as false positives, missing crucial indicators of a real attack.

## Recommendation

*   Implement TTD/TTR as primary metrics to measure SOC effectiveness, using red/purple teaming to generate data.
*   Prioritize hypothesis-led threat hunting to proactively identify potential threats and improve detection capabilities.
*   Establish and maintain hard thresholds for false positive rates to minimize alert fatigue and ensure analysts focus on genuine threats.
*   Evaluate and refine detection rules to maximize true positives and minimize false positives.
*   Focus on the value of collected logs rather than sheer volume to ensure relevant data is available for threat detection.
*   Develop detection rules based on understanding likely attackers and their techniques mentioned in the overview.
