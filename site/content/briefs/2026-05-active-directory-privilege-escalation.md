---
title: Active Directory Privilege Escalation Identified via Correlated Risk Events
slug: 2026-05-active-directory-privilege-escalation
description: This correlation analytic identifies potential privilege escalation activities within an organization's Active Directory (AD) environment by correlating multiple analytics from the Active Directory Privilege Escalation analytic story within a specified time frame, helping identify coordinated attempts to gain elevated privileges which could lead to unauthorized access to sensitive systems and data.
date: "2026-05-28T17:45:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - privilege-escalation
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://attack.mitre.org/tactics/TA0004/
  - https://research.splunk.com/stories/active_directory_privilege_escalation/
rules:
  - title: Detect High Risk Score AD Events
    description: Detects Active Directory events with a high risk score indicating potential privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1484
    data_sources:
      - endpoint
      - splunk
  - title: Detect Multiple Active Directory Privilege Escalation Events on Single System
    description: Detects systems with multiple Active Directory privilege escalation events within a short time frame, indicating a potential attack.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1484
    data_sources:
      - endpoint
      - splunk
rules_count: 2
---

This analytic identifies potential Active Directory (AD) privilege escalation activities by correlating multiple risk events within a specified time frame. It leverages the "Active Directory Privilege Escalation" analytic story in Splunk Enterprise Security and aggregates risk scores and event counts associated with various privilege escalation techniques. The goal is to detect coordinated attempts to gain elevated privileges within the AD environment. This activity is significant because successful privilege escalation can lead to unauthorized access to sensitive systems and data, potentially resulting in data breaches and further network compromise. The detection is based on a minimum number of correlated events (default of 4) from the analytic story.

## Attack Chain

1. An attacker compromises an initial user account through techniques such as phishing or credential stuffing.
2. The attacker leverages the compromised account to enumerate Active Directory objects and identify potential privilege escalation paths.
3. The attacker attempts to exploit vulnerabilities or misconfigurations within Active Directory, such as unconstrained delegation or vulnerable group policies.
4. The attacker gains control of a service account or other privileged account within the domain.
5. The attacker uses the compromised privileged account to modify group memberships or permissions, granting themselves additional privileges.
6. The attacker leverages their elevated privileges to access sensitive systems and data, such as domain controllers or file servers.
7. The attacker moves laterally across the network, compromising additional systems and accounts using their escalated privileges.
8. The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or sabotage.

## Impact

Successful Active Directory privilege escalation can have a significant impact on an organization. Attackers can gain complete control of the domain, access sensitive data, disrupt business operations, and deploy ransomware. The extent of the impact depends on the attacker's objectives and the organization's security posture. In some cases, attackers may remain undetected for extended periods, causing long-term damage to the organization's reputation and financial stability.

## Recommendation

*   Implement Splunk Enterprise Security and enable the "Active Directory Privilege Escalation" analytic story.
*   Tune the `source_count` threshold in the correlation search `active_directory_privilege_escalation_identified_filter` to reflect your environment's baseline activity.
*   Review and modify the risk scores assigned to individual analytics within the analytic story based on their relevance and accuracy in your environment.
*   Investigate correlated risk events identified by this analytic to determine the root cause and scope of the potential privilege escalation attempt.
*   Use the drilldown searches provided to view the detection results and risk events associated with specific risk objects.
*   Monitor for unusual or unauthorized changes to Active Directory group memberships and permissions.
*   Implement multi-factor authentication for privileged accounts to reduce the risk of credential compromise.
