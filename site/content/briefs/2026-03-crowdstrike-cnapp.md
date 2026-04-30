---
title: CrowdStrike Falcon Cloud Security CNAPP with Adversary-Informed Risk Prioritization
slug: 2026-03-crowdstrike-cnapp
description: CrowdStrike's new CNAPP capabilities in Falcon Cloud Security focus on adversary-informed risk prioritization by correlating application-layer visibility with threat actor profiles and techniques, enabling security teams to understand cloud risk, prioritize remediation, and accelerate response.
date: "2026-03-28T08:17:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
  - Scattered Spider
  - UNC3944
  - Octo Tempest
  - Roasted 0ktapus
  - Muddled Libra
  - Star Fraud
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1530
    technique_name: Exploitation of Cloud-Based Applications
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1589
    technique_name: Gather Victim Identity Information
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects overly permissive access to cloud storage resources, which can be exploited by attackers for reconnaissance and data access.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Instance Metadata API Access
    description: Detects suspicious access to the cloud instance metadata API, which could indicate reconnaissance or credential theft attempts.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1589.002
    data_sources:
      - network_connection
      - aws
  - title: Detect Unapproved LLM Usage
    description: Detects network connections to external Large Language Models (LLMs) from applications, which could indicate shadow AI activity or sensitive data exposure.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

CrowdStrike has enhanced its Falcon Cloud Security with new Cloud-Native Application Protection Platform (CNAPP) capabilities designed to prioritize cloud risks based on adversary behavior. This update addresses critical gaps in current CNAPP solutions, including limited visibility into business applications, a lack of integration of adversary intelligence, and difficulties in tracing the root cause of exposures. The new features provide application-layer visibility, correlate risks with threat actor profiles and techniques, and help identify the configuration changes that introduced vulnerabilities. This enables security teams to focus on the attack paths most likely to be exploited by threat actors, such as LABYRINTH CHOLLIMA and SCATTERED SPIDER, and to more effectively prioritize remediation efforts within their cloud environments.

## Attack Chain

1.  **Initial Compromise (Theoretical):** An attacker gains initial access to the cloud environment, potentially exploiting a misconfiguration or vulnerability in a cloud service or application.
2.  **Reconnaissance:** The attacker uses internal reconnaissance techniques to discover cloud resources, application dependencies, and potential attack paths within the cloud environment. This phase can be accelerated by exploiting overly permissive access controls on storage resources.
3.  **Privilege Escalation:** The attacker attempts to elevate privileges within the cloud environment by exploiting weak IAM configurations, vulnerable services, or exposed credentials.
4.  **Lateral Movement:** Using compromised credentials or exploiting service vulnerabilities, the attacker moves laterally to other cloud resources and applications within the environment. The attacker may target business-critical applications that process sensitive data.
5.  **Data Access:** The attacker accesses sensitive data stored in cloud storage, databases, or other resources, potentially including customer PII.
6.  **Exfiltration (Theoretical):** The attacker exfiltrates the stolen data from the cloud environment to an external location.
7.  **Impact (Theoretical):** The successful attack results in data breaches, financial loss, reputational damage, and disruption of business operations.

## Impact

The observed trend of increasing cloud breaches, including a 266% year-over-year surge in cloud-conscious intrusions by state-nexus threat actors in 2025, highlights the critical need for enhanced cloud security measures. Successful attacks can lead to data breaches, financial losses, reputational damage, and disruption of critical business operations, particularly targeting financial services. The Falcon Cloud Security CNAPP aims to reduce the risk of such incidents by providing better visibility, risk prioritization, and faster response times.

## Recommendation

*   Deploy Falcon Cloud Security to gain visibility into application-layer risks and dependencies as described in the overview section.
*   Utilize the adversary intelligence features of Falcon Cloud Security to prioritize cloud risks based on known threat actor profiles and observed techniques, mapping risks to groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
*   Investigate alerts generated by Falcon Cloud Security that indicate potential attack paths used by known threat actors, focusing on the industries they actively target, as mentioned in the threat brief.
*   Enable and review logs from your cloud infrastructure and application services to correlate with the Falcon Cloud Security findings and identify the configuration changes that introduced the exposures.
