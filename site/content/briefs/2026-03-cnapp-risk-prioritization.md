---
title: CrowdStrike Falcon CNAPP Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-risk-prioritization
description: CrowdStrike Falcon Cloud Security introduces new CNAPP capabilities including Application Explorer and adversary intelligence to prioritize cloud risks based on threat actor behavior, enabling security teams to focus on documented intrusion patterns by groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
date: "2026-03-30T06:19:01Z"
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
  - threat-intelligence
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1535
    technique_name: Unprotected Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Suspicious Cloud Resource Enumeration
    description: Detects potential reconnaissance activity through excessive API calls.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Storage Access by Unusual Process
    description: Detects access to cloud storage buckets by processes not typically associated with cloud operations.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1535
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike has enhanced its Falcon Cloud Security with new CNAPP capabilities designed to improve risk prioritization in cloud environments. This update focuses on addressing the limitations of current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage due to a lack of context around configuration changes. The new features, including Application Explorer and adversary intelligence integration, aim to provide security teams with the context needed to understand cloud risk, prioritize remediation efforts, and respond more effectively to potential breaches. Specifically, the system now maps cloud risks against more than 280 adversary groups, including LABYRINTH CHOLLIMA and SCATTERED SPIDER, identifying targeted industries and enabling organizations to prioritize exposures based on documented intrusion patterns. This update was released on March 24, 2026, and is intended to provide more proactive and context-aware cloud security.

## Attack Chain

1. **Initial Foothold:** An attacker gains initial access to the cloud environment, potentially through misconfigured IAM roles or vulnerable applications, exploiting weaknesses in cloud infrastructure.
2. **Discovery:** The attacker uses cloud APIs and native tools to enumerate cloud resources, identify critical applications, and map out the network topology. Tools like `awscli`, `gcloud`, or `az` are used for reconnaissance.
3. **Lateral Movement:** The attacker leverages stolen credentials or compromised service accounts to move laterally within the cloud environment, targeting systems hosting business-critical applications.
4. **Privilege Escalation:** Exploiting misconfigurations or vulnerabilities, the attacker elevates privileges to gain access to sensitive data and critical resources.
5. **Data Access:** The attacker gains access to sensitive data stored in cloud storage services or databases, potentially targeting customer PII or financial information.
6. **Exfiltration:** The attacker exfiltrates the stolen data to an external location, using methods such as cloud storage synchronization or direct network transfers.
7. **Persistence:** The attacker establishes persistence by creating backdoors or modifying cloud configurations to maintain access to the environment even after initial compromises are addressed.
8. **Impact:** The attacker achieves their objectives, which may include data theft, service disruption, or financial gain, causing significant damage to the organization's reputation and bottom line.

## Impact

A successful attack targeting cloud infrastructure can result in significant data breaches, service disruptions, and financial losses. The integration of adversary intelligence helps organizations prioritize risks based on the tactics and techniques employed by known threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER, who are known to target specific industries. The potential impact includes the compromise of business-critical applications, exposure of sensitive customer data, and disruption of essential services, leading to reputational damage and financial penalties. In 2025, cloud-conscious intrusions by state-nexus threat actors surged 266% year-over-year, highlighting the increasing threat landscape in cloud environments.

## Recommendation

*   Deploy the "Detect Suspicious Cloud Resource Enumeration" Sigma rule to identify attackers using cloud APIs for reconnaissance (logsource: cloudtrail, detection: cloudtrail_enumeration).
*   Enable and review cloud audit logs to ensure comprehensive visibility into user and service account activity across your cloud environment (logsource: cloudtrail, azure_monitor, google_cloud).
*   Prioritize remediation of cloud misconfigurations that align with the TTPs of threat actors known to target your industry, as identified by Falcon Cloud Security's adversary intelligence (references: LABYRINTH CHOLLIMA, SCATTERED SPIDER).
*   Implement multi-factor authentication (MFA) for all user and service accounts to prevent unauthorized access to cloud resources (references: CrowdStrike FalconID).
*   Use Application Explorer within Falcon Cloud Security to map application dependencies and identify infrastructure risks that impact business-critical applications.
