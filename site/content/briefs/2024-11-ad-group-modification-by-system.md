---
title: Active Directory Group Modification by SYSTEM Account
slug: 2024-11-ad-group-modification-by-system
description: Detection of a user being added to an Active Directory group by the SYSTEM account (S-1-5-18) can indicate an attacker with SYSTEM privileges attempting to pivot to a domain account.
date: "2024-11-02T23:59:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
  - active directory
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_group_modification_by_system.toml
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Active Directory Group Modification by SYSTEM Account
    description: Detects when a user is added to an Active Directory group by the SYSTEM account (S-1-5-18), indicating potential privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - security
      - windows
  - title: Active Directory Group Modification via SYSTEM with Suspicious Member
    description: Detects SYSTEM account modifying a group and adding a member that is not a standard user.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - security
      - windows
rules_count: 2
---

This detection identifies a user being added to an Active Directory (AD) group by the SYSTEM account (S-1-5-18). This behavior is significant because it can indicate an attacker who has successfully achieved SYSTEM level privileges on a domain controller. Attackers typically obtain SYSTEM privileges by exploiting vulnerabilities in the domain controller, or by abusing default group privileges such as those assigned to Server Operators. Once SYSTEM access is achieved, the attacker can then attempt to pivot to a domain account. This allows them to gain persistent access and control over the AD environment. Successful exploitation enables attackers to perform actions with the privileges of the compromised account, leading to potential data breaches, system compromise, and further lateral movement within the network.

## Attack Chain

1. **Initial Access:** An attacker gains initial access to the network through various means, such as phishing or exploiting a public-facing application.
2. **Privilege Escalation:** The attacker exploits a vulnerability or misconfiguration on a system within the network to achieve local administrator or SYSTEM privileges.
3. **Domain Controller Compromise:** The attacker uses their elevated privileges to target a domain controller, exploiting vulnerabilities or weak configurations to gain SYSTEM access on the domain controller itself.
4. **Group Modification:** Once the attacker has SYSTEM privileges on a domain controller, they use this access to add a user account to a privileged Active Directory group. This is done by modifying the group membership using tools native to the operating system.
5. **Persistence:** By adding a user account to a privileged group, the attacker ensures they have persistent access to the domain, even if their initial access method is discovered and blocked.
6. **Lateral Movement:** With the newly acquired group membership, the attacker can now move laterally within the network, accessing resources and systems that were previously inaccessible.
7. **Data Exfiltration / Impact:** The attacker leverages their access to locate and exfiltrate sensitive data, or to disrupt critical business operations.

## Impact

A successful attack can lead to a wide range of negative consequences, including data breaches, system compromise, and disruption of critical business operations. Attackers can use the compromised account to access sensitive data, modify system configurations, or even deploy ransomware. The scope of impact depends on the permissions and privileges associated with the compromised account and the targeted resources. Furthermore, the incident can damage the organization's reputation and result in regulatory fines and legal liabilities.

## Recommendation

*   Enable "Audit Security Group Management" to generate the necessary events for detection as detailed in the [setup instructions](https://ela.st/audit-security-group-management).
*   Deploy the following Sigma rule to detect potential Active Directory group modifications by the SYSTEM account and tune for your environment.
*   Investigate any event with event code 4728 where the SubjectUserSid is "S-1-5-18" as described in the [overview](#overview).
*   Review the investigation guide outlined in the rule description for triage and analysis steps.
