---
title: Detection of Sensitive LDAP Attribute Access
slug: 2024-01-ldap-attribute-access
description: This rule detects unauthorized access to sensitive Active Directory object attributes such as unixUserPassword, ms-PKI-AccountCredentials, and msPKI-CredentialRoamingTokens, potentially leading to credential theft and privilege escalation.
date: "2024-01-19T16:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - privilege-escalation
  - collection
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
  - Windows Security Event Logs
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1649
    technique_name: Steal or Forge Authentication Certificates
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://www.mandiant.com/resources/blog/apt29-windows-credential-roaming
  - https://social.technet.microsoft.com/wiki/contents/articles/11483.windows-credential-roaming.aspx
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
rules:
  - title: Access to Sensitive LDAP Attributes
    description: Detects access to sensitive Active Directory object attributes containing credentials and decryption keys.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Event 4662 - Access to Sensitive LDAP Attributes
    description: Detects event 4662 related to access of sensitive LDAP attributes in Windows Security Event Logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies attempts to access sensitive attributes within Active Directory via the Lightweight Directory Access Protocol (LDAP). These attributes, including `unixUserPassword`, `ms-PKI-AccountCredentials`, and `msPKI-CredentialRoamingTokens`, are valuable targets for adversaries aiming to steal credentials or escalate privileges. The rule focuses on Windows Security Event Logs, specifically monitoring event code 4662 which indicates an attempt to access an object. By filtering out common benign access patterns, such as those originating from the SYSTEM account or using specific access masks, the rule aims to highlight potentially malicious activity that warrants further investigation. The original rule was created in November 2022 and updated in May 2026.

## Attack Chain

1. An attacker gains initial access to a system within the target domain (e.g., through phishing or exploiting a public-facing application).
2. The attacker uses valid credentials or exploits a vulnerability to authenticate to the domain.
3. The attacker uses LDAP queries to enumerate Active Directory objects.
4. The attacker crafts specific LDAP queries to target sensitive attributes like `unixUserPassword`, `ms-PKI-AccountCredentials`, or `msPKI-CredentialRoamingTokens`.
5. Windows Security Event 4662 is generated, logging the access attempt with details about the user, accessed object, and properties.
6. The attacker exfiltrates the accessed attribute data, potentially containing password hashes, certificates, or other sensitive information.
7. The attacker uses the stolen credentials or certificates to impersonate other users or gain elevated privileges within the domain.

## Impact

Successful exploitation can lead to the compromise of domain accounts, including privileged accounts. Attackers can use stolen credentials to move laterally within the network, access sensitive data, and disrupt business operations. Depending on the attributes accessed, this could also expose private keys and authentication certificates leading to further attacks.

## Recommendation

*   Deploy the Sigma rule "Access to Sensitive LDAP Attributes" to your SIEM to detect access attempts to critical AD attributes (rule.name).
*   Enable "Audit Directory Service Access" to ensure that necessary Windows Security Event Logs (event code 4662) are generated for the Sigma rule to function (setup).
*   Review and tune the "Access to Sensitive LDAP Attributes" Sigma rule, creating exceptions for legitimate administrative accounts and scheduled system processes to minimize false positives (rule.note).
*   Implement stricter access controls and permissions for sensitive LDAP attributes within Active Directory to restrict access to only necessary personnel (rule.note).
*   Investigate any triggered alerts from the Sigma rule, focusing on identifying the user/process attempting access (winlog.event_data.SubjectUserSid) and the specific sensitive attribute accessed (winlog.event_data.Properties) (rule.note).
