---
title: CrowdStrike CNAPP Adds Adversary-Informed Risk Prioritization
slug: 2026-04-cnapp-risk-prioritization
description: CrowdStrike's CNAPP enhancements prioritize cloud risks based on adversary behavior, application context, and configuration change tracking to reduce breach likelihood.
date: "2026-03-29T06:52:03Z"
type: coverage
types:
  - coverage
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
  - cnapp
  - cloud-security
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Credentials from Password Stores
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Resource Access by Uncommon Process
    description: Detects access to cloud resources by processes not typically associated with cloud management, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1556.006
    data_sources:
      - process_creation
      - windows
  - title: Detect Unusual Cloud CLI Tool Execution Location
    description: Detects execution of cloud CLI tools (aws, azure, gcloud) from unusual locations, suggesting potential compromise.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has enhanced its Cloud Native Application Protection Platform (CNAPP) with new features designed to address the limitations of existing cloud risk assessment approaches. Current CNAPP solutions often lack visibility into the application layer, ignore adversary behavior when prioritizing risks, and struggle to connect risk detections to the configuration changes that introduced them. The updated Falcon Cloud Security aims to bridge these gaps by incorporating application context, adversary intelligence, and configuration change tracking. The goal is to help organizations focus on the risks that matter most, based on real-world threat actor tactics and the criticality of affected applications. According to the CrowdStrike 2026 Global Threat Report, cloud intrusions by state-nexus actors increased significantly, underscoring the need for enhanced cloud security measures.

## Attack Chain

1.  Initial Access: Exploit a misconfigured cloud service or application vulnerability to gain initial access to the cloud environment.
2.  Privilege Escalation: Leverage overly permissive access controls or insecure configurations to escalate privileges within the cloud environment.
3.  Lateral Movement: Move laterally across the cloud infrastructure, identifying and accessing critical applications and data stores.
4.  Data Access: Access sensitive data stored within cloud storage resources or databases, such as customer PII.
5.  AI Component Exploitation: Target AI-driven applications, potentially exploiting vulnerabilities in external large language models (LLMs) or unapproved AI model usage.
6.  Data Exfiltration: Exfiltrate sensitive data to external locations, potentially using compromised AI components or insecure network configurations.

## Impact

Successful exploitation of cloud misconfigurations can lead to data breaches, service disruptions, and financial losses. Compromised AI components may expose sensitive data to external AI services or result in unauthorized model usage. The enhanced CNAPP features aim to reduce the likelihood of such incidents by providing better visibility into application dependencies, prioritizing risks based on adversary behavior, and tracking configuration changes that introduce vulnerabilities. Given the observed increase in cloud intrusions, organizations that fail to address these risks face a heightened risk of compromise.

## Recommendation

*   Leverage Falcon Cloud Security's Application Explorer to gain visibility into application dependencies and identify infrastructure risks impacting critical applications (Application Explorer).
*   Prioritize remediation efforts based on the adversary intelligence provided by Falcon Cloud Security, focusing on risks aligned with known threat actor tactics and targeted industries (Adversary Intelligence for Cloud Risks). Specifically focus on the techniques employed by threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
*   Enable Sysmon process creation logging to activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
