---
title: CrowdStrike CNAPP Enhancements for Adversary-Informed Risk Prioritization
slug: 2026-03-crowdstrike-cnapp
description: CrowdStrike's enhanced Cloud Native Application Protection Platform (CNAPP) improves risk prioritization by incorporating threat intelligence from groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER, providing context on application-infrastructure dependencies, and identifying configuration changes leading to exposure.
date: "2026-03-30T06:46:07Z"
type: coverage
types:
  - coverage
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA / SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1530
    technique_name: Exploitation of Cloud Vulnerabilities
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Metadata Service Access
    description: Detects access to cloud metadata services, which can be an early sign of reconnaissance by threat actors in cloud environments.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - network_connection
      - cloudtrail
  - title: Detect Overly Permissive Storage Access
    description: Detects storage resource access with overly permissive configurations, potentially exposing sensitive data to unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has enhanced its CNAPP offering by incorporating adversary-informed risk prioritization. This update addresses limitations in existing CNAPP solutions, which often lack visibility into business applications, ignore specific adversary behaviors, and result in endless triage. The enhanced CNAPP aims to provide security teams with the context needed to understand cloud risks, prioritize remediation efforts, and accelerate the transition from detection to action. A key component involves leveraging CrowdStrike's threat intelligence on over 280 adversary groups, including LABYRINTH CHOLLIMA and SCATTERED SPIDER, to align risks with known attacker tactics. The enhancements released on March 24, 2026, intend to reduce the impact of cloud intrusions, which surged 266% year-over-year in 2025, as reported in the CrowdStrike 2026 Global Threat Report.

## Attack Chain

1.  Initial Access: Adversary gains initial access to the cloud environment, potentially by exploiting misconfigurations or vulnerabilities in cloud services.
2.  Discovery: The attacker performs reconnaissance to map out the cloud infrastructure, identify business applications, and discover dependencies between services.
3.  Privilege Escalation: The attacker attempts to escalate privileges to gain access to sensitive resources and data.
4.  Lateral Movement: The attacker moves laterally within the cloud environment to access additional systems and applications.
5.  Data Access: The attacker targets specific applications, such as those processing PII or payment information, to access sensitive data.
6.  Exfiltration: The attacker exfiltrates the stolen data from the cloud environment to an external location.
7.  Impact: The attacker may cause disruption to business operations, financial loss, or reputational damage.

## Impact

Successful exploitation of cloud misconfigurations and vulnerabilities, as targeted by groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER, can lead to significant data breaches, service disruptions, and financial losses. The CrowdStrike 2026 Global Threat Report indicated a 266% surge in cloud-conscious intrusions during 2025. The enhanced CNAPP aims to mitigate these risks by prioritizing threats aligned with known adversary tactics, techniques, and procedures (TTPs).

## Recommendation

*   Utilize the Application Explorer feature in Falcon Cloud Security to gain visibility into application-infrastructure dependencies and prioritize remediation efforts based on business risk.
*   Leverage CrowdStrike's threat intelligence integration to assess cloud risks based on known adversary profiles and observed techniques, particularly those associated with groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
*   Deploy the Sigma rule below to detect potential reconnaissance activity targeting cloud metadata services, helping to identify early stages of cloud attacks.
*   Enable logging for cloud configuration changes and correlate these changes with risk detections to identify the root cause of exposures.
