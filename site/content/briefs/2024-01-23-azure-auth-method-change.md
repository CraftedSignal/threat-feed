---
title: Azure Authentication Method Change Detection
slug: 2024-01-23-azure-auth-method-change
description: An attacker may add an authentication method to a compromised Azure account for persistent access, which can be detected by monitoring changes to authentication methods in Azure audit logs.
date: "2024-01-23T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-privileged-accounts
rules:
  - title: Azure AD - User Registered Security Info
    description: Detects when a user registers new security info, which could be a sign of account compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1098
      - T1556
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD - Multiple Security Info Changes in Short Time
    description: Detects multiple security info changes within a short time period, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1098
      - T1556
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

Attackers often target cloud environments to establish persistence and maintain unauthorized access. One technique involves adding their own authentication methods to compromised user accounts. By registering a new security info, such as a phone number or email address, an attacker can bypass multi-factor authentication and regain access even if the original credentials are changed. This activity is typically logged within Azure Audit Logs, specifically under the 'Authentication Methods' service and 'UserManagement' category. Detecting these changes is crucial for identifying potentially compromised accounts and preventing further damage.

## Attack Chain

1.  Initial access to the Azure environment is gained, potentially through credential phishing or other means.
2.  The attacker identifies a target user account with sufficient privileges.
3.  The attacker accesses the Azure Active Directory (Azure AD) settings for the compromised user.
4.  The attacker navigates to the "Security info" section of the user's profile.
5.  The attacker registers a new authentication method, such as a phone number or email address, controlled by the attacker. This action generates an audit log event with OperationName "User registered security info".
6.  The attacker can now use the newly added authentication method to bypass multi-factor authentication.
7.  The attacker leverages the compromised account to access sensitive data, applications, or resources within the Azure environment.
8.  The attacker maintains persistent access to the Azure environment, even if the original account password is changed.

## Impact

Successful addition of rogue authentication methods allows attackers to maintain persistent access to compromised accounts within Azure environments. This can lead to data breaches, unauthorized access to sensitive applications, privilege escalation, and lateral movement within the cloud infrastructure. The impact can range from data exfiltration to complete control over the targeted Azure resources.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect changes to authentication methods within Azure audit logs (logsource: azure, service: auditlogs).
*   Investigate any instances where the `OperationName` is `User registered security info` in the Azure Audit Logs, as this indicates a change in authentication method.
*   Review the referenced Microsoft documentation on privileged account security to understand best practices for securing administrative accounts (references).
