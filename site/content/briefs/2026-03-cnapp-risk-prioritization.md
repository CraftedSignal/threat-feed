---
title: CrowdStrike CNAPP Advances with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-risk-prioritization
description: CrowdStrike is enhancing its CNAPP capabilities with adversary-informed risk prioritization, application-layer visibility, and improved risk detection to address gaps in cloud security and reduce breach risks.
date: "2026-03-28T09:14:12Z"
type: coverage
types:
  - coverage
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA and SCATTERED SPIDER
tags:
  - CNAPP
  - cloud-security
  - risk-prioritization
  - threat-intelligence
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
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects potentially overly permissive access configurations in cloud storage resources that could be exploited by threat actors.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Lateral Movement Through Cloud Instance Credentials
    description: Detects use of stolen or compromised credentials from cloud instances.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike is advancing its Cloud Native Application Protection Platform (CNAPP) to provide more effective cloud security. Current CNAPP solutions often lack visibility into business applications, ignore adversary behavior patterns, and create endless triage cycles due to a lack of context. CrowdStrike's enhanced CNAPP capabilities aim to address these limitations by incorporating application-layer visibility, threat intelligence, and automated risk detection. These updates enable organizations to understand how applications interact with infrastructure, prioritize risks based on observed adversary behavior (like that of LABYRINTH CHOLLIMA and SCATTERED SPIDER), and quickly remediate configuration changes that introduce exposure. This approach aims to reduce cloud breaches, which increased by 266% year-over-year in 2025. The new features include Application Explorer and Adversary Intelligence for Cloud Risks.

## Attack Chain

1. **Initial Foothold:** Adversaries identify cloud environments lacking robust CNAPP solutions.
2. **Reconnaissance:** Threat actors, such as LABYRINTH CHOLLIMA and SCATTERED SPIDER, perform reconnaissance to discover overly permissive access configurations in cloud storage resources, utilizing techniques specific to cloud environments.
3. **Application Discovery:** Adversaries leverage discovered misconfigurations to identify business applications connected to the compromised cloud resources.
4. **Lateral Movement:** Using compromised credentials or exploited vulnerabilities, adversaries move laterally within the cloud environment, targeting business-critical applications.
5. **Data Access:** Attackers access sensitive data, such as customer PII, through compromised applications, exploiting the identified infrastructure risks.
6. **AI Component Exploitation:** In AI-driven applications, adversaries identify dependencies on external large language models (LLMs) and attempt to expose sensitive data to unapproved AI services.
7. **Exfiltration:** Sensitive data is exfiltrated from the cloud environment.
8. **Impact:** Data breaches, financial loss, and reputational damage occur as a result of the successful intrusion.

## Impact

Successful exploitation of cloud misconfigurations and vulnerabilities can lead to significant data breaches, financial losses, and reputational damage. The rise in cloud-conscious intrusions by state-nexus threat actors, with a 266% increase year-over-year in 2025, highlights the growing threat. By targeting financial services and other sectors, attackers can compromise sensitive data, disrupt critical business operations, and impact a large number of individuals. The enhanced CNAPP capabilities aim to mitigate these risks by providing better visibility and prioritization of security issues.

## Recommendation

*   Deploy the Sigma rule "Detect Overly Permissive Cloud Storage Access" to identify potential misconfigurations in cloud storage resources, as mentioned in the overview.
*   Enable and monitor Application Explorer in CrowdStrike Falcon Cloud Security to gain visibility into business application dependencies and associated risks.
*   Utilize the adversary intelligence feature in Falcon Cloud Security to prioritize cloud risks based on the observed behavior of threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
*   Review and remediate any risk detections that align with the TTPs of known threat actors, focusing on the conditions attackers target in documented intrusions, as referenced in the "Adversary Intelligence for Cloud Risks" section.
