---
title: Unusual Modification of Delegated Managed Service Account Attribute
slug: 2026-05-dmsa-modification
description: Detection of modifications to the msDS-ManagedAccountPrecededByLink attribute of a delegated managed service account (dMSA) by an unusual subject account, which attackers can abuse to inherit permissions and elevate privileges in Active Directory.
date: "2026-05-12T18:59:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - active-directory
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_badsuccessor_dmsa_abuse.toml
rules:
  - title: Detect Delegated Managed Service Account Modification
    description: Detects modifications to the msDS-ManagedAccountPrecededByLink attribute by an unusual user, indicative of potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - process_creation
      - windows
  - title: Detect Event 5136 with msDS-ManagedAccountPrecededByLink Modification
    description: Detects Windows Event 5136 indicating a modification to the msDS-ManagedAccountPrecededByLink attribute of a dMSA.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - process_creation
      - windows
  - title: Event 5136 with modified msDS-ManagedAccountPrecededByLink
    description: Detects modifications to the msDS-ManagedAccountPrecededByLink attribute of a delegated managed service account
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies suspicious modifications to the `msDS-ManagedAccountPrecededByLink` attribute of a Delegated Managed Service Account (dMSA) within Active Directory environments. Attackers can manipulate this attribute, effectively hijacking the permissions associated with the target account, which leads to privilege escalation. This technique, often referred to as "BadSuccessor", allows an attacker to link a malicious account to a privileged dMSA, granting the attacker unauthorized access and control over critical domain resources. The rule focuses on identifying unusual subject accounts making these modifications, differentiating them from legitimate dMSA management activities. Defenders should prioritize monitoring this activity as it can lead to significant impact on the confidentiality, integrity, and availability of critical systems.

## Attack Chain

1.  An attacker gains initial access to a low-privileged account within the Active Directory domain.
2.  The attacker identifies a target Delegated Managed Service Account (dMSA) with elevated privileges.
3.  Using compromised credentials or exploiting a vulnerability, the attacker attempts to modify the `msDS-ManagedAccountPrecededByLink` attribute of the target dMSA.
4.  The attacker sets the `msDS-ManagedAccountPrecededByLink` attribute to point to an attacker-controlled account. This can be done using tools like PowerShell or AD management tools.
5.  The modification is logged as Event ID 5136 with the `AttributeLDAPDisplayName` of `msDS-ManagedAccountPrecededByLink`.
6.  The attacker authenticates as the attacker-controlled account, now effectively inheriting the privileges of the target dMSA.
7.  The attacker leverages the inherited privileges to perform unauthorized actions, such as accessing sensitive data, modifying critical systems, or creating new administrative accounts.
8.  The attacker achieves persistence and maintains long-term control over the compromised environment.

## Impact

Successful exploitation of this vulnerability can lead to significant privilege escalation within the Active Directory domain. An attacker can gain control over critical resources, compromise sensitive data, and disrupt business operations. The impact includes potential data breaches, financial losses, and reputational damage. The number of potential victims is dependent on the scope of the Active Directory environment.

## Recommendation

*   Enable "Audit Directory Service Changes" to generate the necessary Windows Security Event Logs for detection, specifically Event ID 5136 (see Setup section in the provided documentation).
*   Deploy the Sigma rule "Delegated Managed Service Account Modification by an Unusual User" to your SIEM to detect unauthorized modifications to the `msDS-ManagedAccountPrecededByLink` attribute.
*   Investigate any triggered alerts by reviewing the associated logs, focusing on the `winlog.event_data.ObjectDN`, `winlog.event_data.AttributeValue`, and `winlog.event_data.SubjectUserSid` fields.
*   Monitor authentication events for the linked dMSA and superseded accounts (`winlog.event_data.TargetUserName`) to identify any unusual activity.
*   Restrict dMSA creation/migration rights to only authorized personnel.
