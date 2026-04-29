---
title: CrowdStrike CNAPP Enhancements for Adversary-Informed Risk Prioritization
slug: 2026-03-crowdstrike-cnapp
description: CrowdStrike's new CNAPP capabilities, including Application Explorer and Adversary Intelligence, enable security teams to prioritize cloud risks based on application context and known adversary behaviors, such as those of LABYRINTH CHOLLIMA and SCATTERED SPIDER, improving remediation efforts.
date: "2026-03-28T08:29:13Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - cloud-security
  - cnapp
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
  - title: Detect Potential Lateral Movement via New Process Execution in Cloud Environments
    description: Detects potential lateral movement attempts by identifying new process executions within cloud environments that are not part of the standard operating procedures.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - process_creation
      - linux
  - title: Detect AI Application Discovery via Network Connection to LLMs
    description: Detects potential AI application discovery by identifying network connections to known Large Language Model (LLM) services from cloud instances, indicating possible Shadow AI usage.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1518
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) with new capabilities designed to bridge critical gaps in cloud security. These enhancements aim to provide security teams with a more comprehensive understanding of cloud risks and to enable better-prioritized remediation efforts. The key additions include Application Explorer, which offers visibility into how business applications interact with cloud infrastructure, and Adversary Intelligence for Cloud Risks, which applies threat intelligence to prioritize risks based on known adversary behaviors and targeted industries. According to the CrowdStrike 2026 Global Threat Report, cloud-conscious intrusions by state-nexus threat actors surged 266% year-over-year, highlighting the need for improved cloud security measures. These capabilities are designed to address the limitations of current CNAPP solutions, which often lack application-layer visibility, ignore adversary behavior, and result in endless triage.

## Attack Chain

1.  **Initial Cloud Infrastructure Compromise:** An attacker gains initial access to the cloud environment, potentially through misconfigurations or vulnerabilities in cloud services.
2.  **Privilege Escalation:** The attacker attempts to escalate privileges within the cloud environment to gain control over more resources.
3.  **Application Discovery:** Using tools and techniques, the attacker identifies critical business applications running within the compromised cloud infrastructure. This includes identifying dependencies and data access patterns.
4.  **Data Access:** The attacker leverages compromised credentials or vulnerabilities to access sensitive data within the targeted applications, such as customer PII.
5.  **Lateral Movement:** The attacker uses the compromised applications and data to move laterally to other parts of the cloud environment or to on-premises systems.
6.  **Shadow AI Discovery:** The attacker identifies AI-driven applications and their dependencies on external large language models (LLMs), potentially uncovering shadow AI usage.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised applications and systems.
8.  **Impact:** The attacker achieves their final objective, such as data theft, financial gain, or disruption of services.

## Impact

Successful exploitation using the described attack chain can lead to significant data breaches, financial losses, and reputational damage. The targeted industries include financial services, as identified by CrowdStrike's threat intelligence on groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER. A successful attack can expose customer PII, intellectual property, and other sensitive data, leading to regulatory fines and legal liabilities. The increasing sophistication of cloud-conscious threat actors, as highlighted in the 2026 Global Threat Report, underscores the importance of proactive cloud security measures.

## Recommendation

*   Implement Application Explorer within Falcon Cloud Security to gain visibility into how business applications interact with cloud infrastructure, enabling a better understanding of application-layer risks.
*   Leverage Adversary Intelligence for Cloud Risks to prioritize remediation efforts based on known adversary profiles and observed techniques, focusing on threat actors targeting specific industries.
*   Use Falcon Cloud Security to identify AI-driven applications and their dependencies on external LLMs, enabling the discovery of shadow AI activity and prevention of sensitive data exposure.
*   Enable and review cloud provider logs (AWS CloudTrail, Azure Activity Log, GCP Audit Logs) for unusual activity or misconfigurations.
