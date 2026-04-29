---
title: CrowdStrike CNAPP Advances with Adversary-Informed Risk Prioritization
slug: 2026-03-cnapp-advances
description: CrowdStrike's new CNAPP capabilities in Falcon Cloud Security address limitations in cloud risk assessment by providing application layer visibility, attacker-aligned risk prioritization based on threat actor profiles and observed techniques, and configuration change tracking to expedite remediation.
date: "2026-03-28T08:13:07Z"
type: coverage
types:
  - coverage
severities:
  - medium
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
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021.002
    technique_name: 'Remote Services: SMB/Windows Admin Shares'
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
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
rules:
  - title: Detect Overly Permissive Cloud Storage Access
    description: Detects attempts to access cloud storage resources with overly permissive access policies.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Outbound Connection from Cloud Application
    description: Detects outbound connections from cloud applications to external AI services or unusual destinations.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CrowdStrike has announced advancements in its Cloud Native Application Protection Platform (CNAPP) within Falcon Cloud Security. This aims to address critical gaps in cloud risk assessment by incorporating application layer visibility, adversary intelligence, and configuration change tracking. With cloud breaches continuing to rise, even with CNAPP adoption, this update seeks to improve proactive security measures. The new capabilities focus on understanding how applications interact with infrastructure, aligning risks with observed adversary behavior, and identifying the root cause of exposures to accelerate the remediation process. This is crucial for organizations struggling with alert fatigue and the inability to prioritize risks effectively in complex cloud environments, especially with the surge in cloud-conscious intrusions by state-nexus threat actors by 266% year-over-year in 2025.

## Attack Chain

1.  An attacker identifies a cloud environment with overly permissive access to a storage resource.
2.  The attacker leverages publicly available tools or custom scripts to enumerate accessible cloud resources.
3.  The attacker uses compromised credentials, or exploits a misconfiguration, to gain unauthorized access to the storage resource.
4.  The attacker maps out application dependencies to identify critical business applications connected to the vulnerable resource using techniques aligned with threat actors like LABYRINTH CHOLLIMA or SCATTERED SPIDER.
5.  The attacker exploits a vulnerability within the identified application to escalate privileges or gain unauthorized access to sensitive data.
6.  The attacker moves laterally within the cloud environment, targeting other interconnected services and resources based on the application's dependencies.
7.  The attacker exfiltrates sensitive data, such as customer PII or proprietary information, from the compromised application or related services.
8.  The attacker attempts to persist within the environment by creating backdoors or modifying configurations, ensuring continued access for future malicious activities.

## Impact

Successful exploitation of cloud misconfigurations and vulnerabilities can lead to significant data breaches, service disruptions, and financial losses. The increase in cloud-conscious intrusions by state-nexus threat actors by 266% in 2025 demonstrates the growing threat landscape. Impacted organizations could face regulatory fines, reputational damage, and loss of customer trust. The compromise of AI-driven applications could expose sensitive data to external AI services, leading to further data leaks and privacy violations.

## Recommendation

*   Leverage Falcon Cloud Security's Application Explorer to gain unified visibility of application dependencies and infrastructure risks, enabling a better understanding of potential attack paths.
*   Utilize the Adversary Intelligence feature in Falcon Cloud Security to prioritize cloud risks based on known adversary profiles and observed techniques. This allows security teams to focus on threats most likely to target their industry and environment.
*   Investigate and remediate overly permissive access configurations on storage resources identified by Falcon Cloud Security to reduce the attack surface.
*   Deploy and tune the Sigma rule `Detect Overly Permissive Cloud Storage Access` to identify potential unauthorized access attempts.
*   Monitor for unusual network activity originating from cloud applications, especially those connecting to external AI services, using network connection logs and the `Detect Suspicious Outbound Connection from Cloud Application` Sigma rule.
*   Enable detailed logging for cloud configuration changes to facilitate investigations into the root cause of exposures and identify who made the changes.
