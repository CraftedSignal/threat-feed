---
title: CrowdStrike CNAPP Enhancements Prioritize Adversary-Informed Cloud Risks
slug: 2026-04-cnapp-risk-prioritization
description: CrowdStrike's new CNAPP capabilities enhance cloud risk assessment by incorporating application-layer visibility, adversary intelligence, and configuration change tracking, enabling security teams to prioritize remediation based on real-world threat actor behavior such as LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-30T09:13:17Z"
type: coverage
types:
  - coverage
severities:
  - high
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - risk-prioritization
  - threat-intelligence
  - adversary-emulation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1530
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects overly permissive access configurations on cloud storage services, which can be exploited for initial access and data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Shadow AI LLM Usage
    description: Detects applications using external Large Language Models (LLMs) that may not be approved or monitored, leading to potential data exposure.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) with new features designed to address limitations in current cloud risk assessment methodologies. These enhancements, released in March 2026, focus on providing comprehensive visibility, intelligent risk prioritization, and actionable insights. The key features include Application Explorer, which provides application-layer visibility, and adversary intelligence integration, which prioritizes risks based on the observed behavior of threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER. The enhancements aim to reduce alert fatigue and enable security teams to focus on the most critical risks that align with real-world threat actor tactics, techniques, and procedures (TTPs). According to the CrowdStrike 2026 Global Threat Report, cloud-conscious intrusions by state-nexus threat actors surged 266% year-over-year in 2025, highlighting the increasing importance of proactive cloud security measures.

## Attack Chain

1. **Initial Access:** An attacker identifies a cloud environment with misconfigured storage resources through reconnaissance.
2. **Credential Access:** The attacker exploits overly permissive access controls on a storage resource to gain access to stored credentials.
3. **Discovery:** The attacker uses the compromised credentials to enumerate applications connected to the storage resource and identifies those processing sensitive data, such as customer PII.
4. **Lateral Movement:** The attacker leverages application dependencies to move laterally to other cloud services and resources within the environment.
5. **Collection:** The attacker targets AI-driven applications to discover shadow AI activity and identifies dependencies on external large language models (LLMs).
6. **Exfiltration:** The attacker exfiltrates sensitive data, including customer PII, by exploiting unapproved model usage and exposing data to external AI services.
7. **Impact:** The attacker achieves their objective by accessing and potentially selling or using the exfiltrated sensitive data for malicious purposes.

## Impact

The enhanced CNAPP capabilities are designed to mitigate the increasing risk of cloud breaches, which saw a 266% surge in intrusions by state-nexus actors in 2025. If attackers successfully exploit cloud misconfigurations and vulnerabilities, organizations could experience data breaches, financial losses, reputational damage, and regulatory penalties. The integration of adversary intelligence helps organizations prioritize and address risks that align with the documented TTPs of known threat actors, reducing the likelihood of successful attacks.

## Recommendation

*   Deploy the Sigma rule for detecting overly permissive storage access to identify potential initial access points, focusing on cloud environments (AWS S3 buckets, Azure Blob Storage, Google Cloud Storage) and tune for your environment.
*   Implement the Sigma rule for identifying shadow AI activity and unauthorized LLM usage to prevent sensitive data exposure to external AI services.
*   Utilize Falcon Cloud Security's Application Explorer to gain visibility into application dependencies and identify potential lateral movement paths.
*   Prioritize remediation efforts based on the adversary intelligence provided by Falcon Cloud Security, focusing on risks aligned with the TTPs of threat actors known to target your industry.
