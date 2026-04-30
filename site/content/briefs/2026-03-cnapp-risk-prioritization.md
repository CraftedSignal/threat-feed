---
title: CrowdStrike Falcon Cloud Security Introduces Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-risk-prioritization
description: CrowdStrike's Falcon Cloud Security enhances CNAPP capabilities by introducing adversary-informed risk prioritization, application layer visibility, and root cause analysis of configuration changes, enabling security teams to better understand and remediate cloud risks.
date: "2026-03-28T09:26:44Z"
type: coverage
types:
  - coverage
severities:
  - medium
actors:
  - LABYRINTH CHOLLIMA
  - SCATTERED SPIDER
tags:
  - cloud
  - cnapp
  - risk-prioritization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Anomalous Access to Cloud Storage Resources
    description: Detects potentially malicious access to cloud storage resources based on deviations from established access patterns.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud Resource Enumeration by Known Threat Actors
    description: Detects potential cloud resource enumeration activities associated with known threat actors.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CrowdStrike Falcon Cloud Security has introduced new Cloud Native Application Protection Platform (CNAPP) capabilities focused on improving risk assessment and remediation in cloud environments. The updates address limitations such as lack of application layer visibility, ignoring adversary behavior, and difficulty in tracing the origin of exposures. Falcon Cloud Security now incorporates Application Explorer, providing application-layer visibility, and adversary intelligence, aligning risk prioritization with known threat actor behaviors (like LABYRINTH CHOLLIMA and SCATTERED SPIDER) and observed intrusion patterns. Additionally, it provides insights into the configuration changes leading to identified exposures. These enhancements aim to provide security teams with better context, enabling them to understand cloud risk, prioritize remediation efforts, and accelerate the transition from detection to action.

## Attack Chain

1.  **Initial Compromise:** An organization's cloud infrastructure is misconfigured, creating an overly permissive access control to a storage resource containing customer PII.
2.  **Discovery:** An adversary, potentially aligned with a group like LABYRINTH CHOLLIMA or SCATTERED SPIDER, identifies the misconfigured storage resource through reconnaissance activities.
3.  **Lateral Movement:** The adversary uses the initial access to move laterally within the cloud environment, exploiting existing roles and permissions.
4.  **Privilege Escalation:** The adversary elevates privileges to gain access to sensitive applications, exploiting vulnerabilities or misconfigurations.
5.  **Data Access:** The attacker accesses applications connected to the storage resource, including business-critical applications processing payment information.
6.  **Data Exfiltration:** The adversary exfiltrates sensitive customer PII from the storage resource, taking advantage of the permissive access controls.
7.  **Impact:** The exfiltrated data is used for malicious purposes, such as identity theft or financial fraud, leading to financial and reputational damage for the targeted organization.

## Impact

The enhanced CNAPP capabilities aim to reduce the likelihood and impact of cloud breaches. In 2025, cloud intrusions by state-nexus threat actors surged by 266%. Successfully exploiting cloud misconfigurations can lead to significant data breaches, financial losses, and reputational damage. Organizations across various sectors, especially financial services, are at risk. Failure to prioritize and remediate cloud risks can result in the compromise of business-critical applications and sensitive data, including personally identifiable information (PII).

## Recommendation

*   Prioritize deployment of Falcon Cloud Security to gain application-layer visibility and identify infrastructure risks impacting critical applications as described in the **Overview**.
*   Utilize the adversary intelligence feature in Falcon Cloud Security to prioritize risk remediation based on known threat actor behavior, specifically focusing on groups like **LABYRINTH CHOLLIMA and SCATTERED SPIDER** as mentioned in the **Overview**.
*   Implement the following Sigma rule to detect anomalous access to cloud storage resources.
*   Enable and review cloud configuration logs to identify misconfigurations leading to overly permissive access controls, enabling faster remediation and prevention of future exposures, as described in the **Attack Chain**.
