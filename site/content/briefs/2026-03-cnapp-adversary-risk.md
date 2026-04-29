---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-adversary-risk
description: CrowdStrike enhances its CNAPP by incorporating adversary-informed risk prioritization, including application-layer analysis and correlation of cloud risks with threat actor profiles like LABYRINTH CHOLLIMA and SCATTERED SPIDER, to enable better risk understanding and remediation.
date: "2026-03-30T06:24:43Z"
type: coverage
types:
  - coverage
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA, SCATTERED SPIDER
tags:
  - cloud-security
  - cnapp
  - risk-prioritization
  - threat-intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Resource Access by Uncommon Process
    description: Detects processes not normally associated with cloud resource access attempting to connect to cloud storage or compute services, indicating potential lateral movement or privilege escalation
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.007
    data_sources:
      - network_connection
      - windows|linux|macos
  - title: Detect Cloud Instance Metadata API Access Attempt
    description: Detects attempts to access cloud instance metadata API from outside the instance, which could indicate credential harvesting or lateral movement.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552.005
    data_sources:
      - network_connection
      - windows|linux|macos
rules_count: 2
---

CrowdStrike has announced advancements to its Cloud-Native Application Protection Platform (CNAPP) with the introduction of adversary-informed risk prioritization. This enhancement addresses limitations in current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage. The new capabilities in CrowdStrike Falcon Cloud Security include Application Explorer, which unifies application-layer visibility with cloud infrastructure context, and threat intelligence integration, which maps cloud risks to known adversary profiles and observed techniques. This enables security teams to prioritize remediation based on real-world threat actor behavior, such as the TTPs employed by groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER. The goal is to provide security teams with the context needed to understand cloud risk, prioritize remediation, and accelerate detection and response within cloud environments. In 2025, cloud-conscious intrusions by state-nexus threat actors surged 266% year-over-year, highlighting the need for this enhanced risk prioritization.

## Attack Chain

1.  Initial Access: Adversaries target cloud environments, potentially exploiting misconfigurations or vulnerabilities in cloud services to gain initial access.
2.  Privilege Escalation: Once inside the cloud environment, adversaries attempt to escalate privileges, potentially exploiting overly permissive access controls or IAM roles.
3.  Lateral Movement: Adversaries move laterally within the cloud environment, leveraging compromised credentials or exploiting vulnerabilities in interconnected services.
4.  Application Discovery: Adversaries use techniques to discover business applications running in the cloud and on-premises environments.
5.  Data Access: Adversaries target storage resources containing sensitive data, such as customer PII, leveraging overly permissive access or stolen credentials.
6.  AI Component Exploitation: In AI-driven applications, adversaries may identify and exploit dependencies on external large language models (LLMs) to expose sensitive data.
7.  Exfiltration: Adversaries exfiltrate sensitive data from compromised cloud resources.
8.  Impact: The final objective is to cause disruption, steal valuable information, or achieve other malicious goals.

## Impact

Successful exploitation of cloud risks can lead to significant data breaches, financial losses, and reputational damage. Given the rise of cloud-conscious intrusions by state-nexus threat actors (266% year-over-year increase in 2025), organizations across all sectors are at risk. Failure to properly prioritize and remediate cloud risks can result in sensitive data exposure, disruption of critical business applications, and compromise of AI-driven services.

## Recommendation

*   Implement Application Explorer to gain visibility into how business applications interact with cloud infrastructure, and identify potential risks affecting production applications. Reference: Application Explorer within CrowdStrike Falcon Cloud Security.
*   Prioritize cloud risks based on adversary intelligence, mapping detections to known threat actor profiles and TTPs (e.g., LABYRINTH CHOLLIMA, SCATTERED SPIDER) within Falcon Cloud Security.
*   Analyze and remediate configuration changes that introduce cloud exposures. Understand the causality and who made the changes to reduce potential breach impacts. Reference: CrowdStrike Falcon Cloud Security new CNAPP innovations.
