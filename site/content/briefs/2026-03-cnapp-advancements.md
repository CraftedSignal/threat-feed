---
title: CrowdStrike Falcon Cloud Security Advances CNAPP with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-advancements
description: CrowdStrike Falcon Cloud Security enhances its CNAPP capabilities, incorporating adversary intelligence to prioritize cloud risks based on threat actor behavior, particularly focusing on groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER, to enable security teams to understand and remediate cloud exposures more effectively.
date: "2026-03-30T06:43:41Z"
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
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Standard Permission Groups Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Processes Accessing Cloud Resources with Unusual User Agent
    description: Detects processes accessing cloud resources (e.g., AWS S3, Azure Blob Storage, Google Cloud Storage) with unusual user agents, potentially indicating unauthorized access or exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1589.002
    data_sources:
      - network_connection
      - windows|linux|macos
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects instances where cloud storage resources (e.g., AWS S3 buckets, Azure Blob containers) are configured with overly permissive access policies, potentially leading to data breaches.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1530
    data_sources:
      - webserver
      - linux|windows
rules_count: 2
---

CrowdStrike has enhanced its Falcon Cloud Security with new CNAPP (Cloud-Native Application Protection Platform) capabilities designed to provide more proactive and context-aware cloud security. These advancements address limitations in current CNAPP solutions, which often lack visibility into business applications, ignore adversary behavior, and result in endless triage due to a lack of causality information. The new features, including Application Explorer and adversary-informed risk prioritization, aim to provide security teams with the necessary context to understand cloud risks, prioritize remediation efforts, and quickly respond to potential breaches by threat actors, with a specific focus on groups like LABYRINTH CHOLLIMA and SCATTERED SPIDER who are known to target cloud environments. According to the CrowdStrike 2026 Global Threat Report, cloud-conscious intrusions by state-nexus threat actors surged 266% year-over-year in 2025, highlighting the need for improved cloud security measures.

## Attack Chain

1.  **Initial Access:** Adversaries gain initial access to the cloud environment through various means, such as exploiting misconfigurations or vulnerabilities in cloud services.
2.  **Discovery:** Threat actors perform reconnaissance to discover cloud resources, services, and applications.
3.  **Lateral Movement:** Attackers move laterally within the cloud environment, leveraging compromised credentials or exploiting vulnerabilities to access additional resources.
4.  **Privilege Escalation:** Adversaries escalate privileges to gain higher-level access to critical cloud resources and data.
5.  **Data Access:** Attackers access sensitive data stored in cloud storage resources, databases, or applications.
6.  **Exfiltration:** The stolen data is exfiltrated from the cloud environment to an external location controlled by the attacker.
7.  **Impact:** The exfiltration of sensitive data can lead to financial loss, reputational damage, and regulatory penalties for the victim organization.

## Impact

A successful cloud breach can result in significant damage, including data theft, financial losses, and reputational harm. The enhanced CNAPP capabilities in CrowdStrike Falcon Cloud Security aim to mitigate these risks by providing organizations with better visibility into cloud assets, risk prioritization based on adversary behavior, and faster remediation capabilities. Specifically, organizations operating in sectors targeted by groups like LABYRINTH CHOLLIMA or SCATTERED SPIDER are at increased risk. In 2025, cloud intrusions increased dramatically, underscoring the urgent need for more effective cloud security measures.

## Recommendation

*   Deploy the Application Explorer to gain visibility into how business applications run across cloud and on-premises environments and identify application-layer risks.
*   Utilize the adversary intelligence feature in Falcon Cloud Security to prioritize cloud risks based on the tactics, techniques, and procedures (TTPs) of known threat actors like LABYRINTH CHOLLIMA and SCATTERED SPIDER.
*   Monitor for overly permissive access to storage resources that connect to applications processing customer personally identifiable information (PII) using a rule like the one below to detect potential data breaches.
*   Implement the Sigma rule below to identify processes accessing cloud resources with unusual user agents, which can indicate unauthorized access attempts or exploitation activity.
