---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-advances
description: CrowdStrike has enhanced its CNAPP capabilities by adding application-layer visibility and prioritizing risks based on known adversary tactics, techniques, and procedures (TTPs).
date: "2026-03-28T14:46:06Z"
type: coverage
types:
  - coverage
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA
  - SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Potential Lateral Movement via API calls
    description: Detects potential lateral movement within a cloud environment by monitoring API calls associated with accessing different compute instances or services.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.007
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Discovery of Cloud Storage Buckets
    description: Detects attempts to discover cloud storage buckets, which could be an attacker mapping the environment.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1526
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has advanced its Cloud-Native Application Protection Platform (CNAPP) to address limitations in current cloud security approaches. The enhancements include Application Explorer, which provides application-layer visibility alongside cloud infrastructure context, and adversary intelligence for cloud risks. These updates aim to help organizations understand how applications interact with infrastructure and prioritize risks based on threat actor behavior. Specifically, the CNAPP maps cloud risks to over 280 adversary groups tracked by CrowdStrike, such as LABYRINTH CHOLLIMA and SCATTERED SPIDER. This allows security teams to focus on exploitation chains known to be used against specific industries and organizational profiles, moving beyond theoretical risk assessments.

## Attack Chain

1.  **Initial Compromise:** An attacker gains initial access to a cloud environment through compromised credentials or exploitation of a vulnerability in a cloud service. (TA0001)
2.  **Privilege Escalation:** The attacker attempts to elevate privileges within the cloud environment to gain access to more sensitive resources and data.
3.  **Lateral Movement:** Using the compromised credentials or elevated privileges, the attacker moves laterally within the cloud environment to identify and access target applications and data stores.
4.  **Application Discovery:** The attacker uses Application Explorer (if available) to map application dependencies, identify business-critical applications, and locate AI components (MCPs, LLMs) within the environment.
5.  **Data Exfiltration:** The attacker identifies storage resources or data stores containing sensitive information (e.g., PII) and attempts to exfiltrate the data to an external location.
6.  **Shadow AI Exploitation:** The attacker exploits shadow AI activity by identifying unapproved model usage and exposing sensitive data to external AI services.
7.  **Persistence:** The attacker establishes persistence within the environment to maintain access and continue their activities even if initial access methods are remediated. (TA0003)

## Impact

The impact of a successful attack can range from data breaches and financial losses to reputational damage and disruption of critical business operations. Specific consequences include the compromise of business-critical applications (e.g., payment processing, hospital ERP), exposure of sensitive data (e.g., PII), and the exploitation of AI-driven applications through shadow AI activity. In 2025, cloud-conscious intrusions by state-nexus threat actors surged 266% year-over-year, highlighting the increasing risk and potential impact of cloud-based attacks.

## Recommendation

*   Leverage Falcon Cloud Security's Application Explorer to gain visibility into application dependencies, identify business-critical applications, and map infrastructure risks affecting production applications.
*   Utilize the adversary intelligence feature within Falcon Cloud Security to prioritize cloud risks based on known adversary profiles and observed techniques, focusing on groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
*   Deploy the Sigma rules below to detect suspicious activity related to common cloud attack patterns in your environment.
*   Review and harden overly permissive access controls on storage resources identified by CrowdStrike.
