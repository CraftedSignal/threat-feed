---
title: Windows Computer Account Changed to Domain Controller
slug: 2024-01-03-windows-computer-account-domain-controller
description: Detects modifications to a Windows computer account's User Account Control flags, specifically the `SERVER_TRUST_ACCOUNT` flag, potentially indicating unauthorized domain controller promotion or privilege escalation within Active Directory.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - active-directory
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136
    technique_name: Create Account
references:
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4742
  - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
rules:
  - title: Windows Computer Account Changed to Domain Controller (Sigma)
    description: Detects a modification to the User Account Control flags for a computer account where the `SERVER_TRUST_ACCOUNT` flag is set. This flag is normally associated with domain controller computer accounts.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136.002
    data_sources:
      - process_creation
      - windows
  - title: Windows Computer Account Changed to Domain Controller (CommandLine)
    description: Detects potential attempts to modify computer account attributes via command-line tools like net.exe
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying suspicious modifications to Windows computer accounts that could indicate malicious activity within an Active Directory environment. Specifically, it monitors for the setting of the `SERVER_TRUST_ACCOUNT` flag in the User Account Control attributes of a computer account. This flag is typically associated with domain controllers, and unexpected changes to this flag might indicate a rogue domain controller promotion or an attempt to grant domain controller-like privileges to a regular computer account. Such actions could be part of a privilege escalation or persistence strategy, allowing attackers to gain control over the domain. The original detection was published on 2026-05-05 and it is important to differentiate legitimate domain controller promotions from malicious attempts to manipulate computer account attributes. Defenders should investigate any unexpected occurrences of this event.

## Attack Chain

1.  An attacker gains initial access to a compromised host within the target network.
2.  The attacker enumerates existing computer accounts within the Active Directory environment.
3.  The attacker identifies a suitable computer account to target for privilege escalation.
4.  The attacker uses a tool or script (e.g., PowerShell, ADSI) to modify the User Account Control attribute of the target computer account.
5.  Specifically, the attacker sets the `SERVER_TRUST_ACCOUNT` flag (%%2088) in the UserAccountControl attribute.
6.  This modification grants the computer account domain controller-like trust within Active Directory.
7.  The attacker leverages this elevated trust to perform actions normally reserved for domain controllers, such as modifying group policies or accessing sensitive data.
8.  The attacker establishes persistence within the domain by using the compromised computer account to maintain unauthorized access.

## Impact

Successful modification of a computer account to mimic a domain controller can have significant impact. Attackers can leverage the elevated privileges to compromise the entire Active Directory domain, potentially affecting thousands of users and systems. This can lead to data breaches, service disruptions, and significant financial losses. The targeted sectors would be broad, ranging from government to finance to healthcare, due to the widespread use of Active Directory in enterprise environments. The risk score is 50 for the affected system.

## Recommendation

*   Deploy the `Windows Computer Account Changed to Domain Controller` Sigma rule to your SIEM and tune for your environment to detect unexpected modifications to the User Account Control attribute.
*   Enable Windows Event Log Security auditing, specifically Event ID 4742, to capture User Account Control changes as outlined in the detection's data_source.
*   Filter alerts originating from authorized IT personnel or approved change management processes as mentioned in known_false_positives.
*   Review and restrict the permissions required to modify User Account Control attributes on computer accounts to minimize the attack surface as the detection covers.
*   Investigate any alerts generated by the Sigma rule promptly to determine whether a legitimate domain controller promotion is occurring or if malicious activity is suspected.
*   Regularly review Active Directory security logs for suspicious activity related to computer account modifications as suggested by the reference links.
