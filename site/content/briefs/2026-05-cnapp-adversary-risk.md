---
title: CrowdStrike CNAPP Enhanced with Adversary-Informed Risk Prioritization
slug: 2026-05-cnapp-adversary-risk
description: CrowdStrike enhances its CNAPP capabilities by incorporating adversary intelligence for risk prioritization, application-layer visibility, and runtime analysis, addressing critical gaps in cloud security and enabling faster remediation based on threat actor behavior like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-29T07:29:13Z"
type: threat
types:
  - threat
severities:
  - high
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
  - cloud_security
  - cnapp
  - threat_intelligence
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1530
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Cloud Account with Excessive Permissions
    description: Detects cloud accounts that have been granted excessive permissions, which can be abused by attackers for lateral movement and data access.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Publicly Accessible Cloud Storage Bucket
    description: Detects when a cloud storage bucket (e.g., AWS S3) is made publicly accessible, potentially exposing sensitive data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AI Model Exposure
    description: Detects when an application interacts with an external AI model, potentially leading to data exposure to an external service.
    platform: sigma
    severity: low
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

CrowdStrike has advanced its Cloud Native Application Protection Platform (CNAPP) by introducing new capabilities designed to provide security teams with improved context and prioritization for cloud risks. The enhanced CNAPP incorporates Application Explorer for application-layer visibility, allowing a unified view of applications running across cloud and on-premises environments. A key feature is the integration of adversary intelligence, which maps cloud risks to known threat actor profiles, such as LABYRINTH CHOLLIMA and SCATTERED SPIDER, enabling risk prioritization based on observed attacker behavior and targeted industries. These advancements aim to close security gaps and reduce breach risks, addressing the rise in cloud intrusions, which surged 266% year-over-year in 2025, as highlighted in the CrowdStrike 2026 Global Threat Report. The CNAPP enhancements also include runtime analysis to understand how applications interact with infrastructure, improving the ability to remediate issues effectively.

## Attack Chain

1.  **Initial Compromise (Cloud Misconfiguration):** An organization's cloud environment contains misconfigured storage resources with overly permissive access. This is often a result of configuration drift or human error.
2.  **Discovery (Application Inventory):** An attacker identifies the organization uses cloud-based infrastructure, and begins reconnaissance to determine publicly accessible services and data stores. They use publicly available cloud enumeration tools.
3.  **Privilege Escalation (Exploit Weak IAM):** The attacker exploits weak Identity and Access Management (IAM) policies to gain access to a service account with broad permissions.
4.  **Lateral Movement (Application Dependency Mapping):** The attacker identifies business-critical applications connected to the storage resource using application dependency mapping and runtime analysis.
5.  **Data Access (PII Exposure):** The attacker accesses the compromised storage resource containing customer Personally Identifiable Information (PII) because the application processes sensitive data.
6.  **Exfiltration (Data Theft):** The attacker exfiltrates the sensitive data to an external controlled server, leveraging the compromised service account.
7.  **Impact (Data Breach):** The organization experiences a data breach, resulting in financial losses, reputational damage, and regulatory fines due to the exposed PII.

## Impact

Successful exploitation of cloud misconfigurations and vulnerabilities can lead to significant data breaches, resulting in financial losses, reputational damage, and regulatory penalties. The 2026 Global Threat Report indicates a 266% surge in cloud intrusions by state-nexus threat actors in 2025, highlighting the increasing risk and potential for widespread impact across various sectors. Organizations operating in targeted industries, such as financial services (a known target of groups like LABYRINTH CHOLLIMA), face a higher likelihood of being compromised. The compromise of AI-driven applications can expose sensitive data to external AI services, further exacerbating the impact.

## Recommendation

*   Deploy the Sigma rule "Detect Cloud Account with Excessive Permissions" to identify accounts with overly permissive access as described in the attack chain (related to Initial Compromise).
*   Leverage CrowdStrike's adversary intelligence to prioritize cloud risks associated with threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER (Adversary Intelligence for Cloud Risks).
*   Utilize Application Explorer to gain visibility into application dependencies and identify business-critical applications connected to cloud resources to focus remediation efforts effectively (Application Explorer).
*   Monitor cloud environments for suspicious activity using cloud-native logging and alerting mechanisms to detect lateral movement and data exfiltration attempts (Attack Chain steps 3-6).
