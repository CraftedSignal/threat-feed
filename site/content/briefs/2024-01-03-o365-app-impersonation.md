---
title: O365 ApplicationImpersonation Role Assigned
slug: 2024-01-03-o365-app-impersonation
description: Detection of the ApplicationImpersonation role being assigned in Office 365, potentially leading to unauthorized mailbox access and impersonation.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - NOBELIUM Group
tags:
  - cloud
  - o365
  - applicationimpersonation
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://attack.mitre.org/techniques/T1098/002/
  - https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452
  - https://www.mandiant.com/media/17656
rules:
  - title: O365 ApplicationImpersonation Role Assigned
    description: Detects the assignment of the ApplicationImpersonation role in Office 365.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1098.002
    data_sources:
      - o365
      - o365
  - title: O365 ApplicationImpersonation Role Assigned to Application
    description: Detects the assignment of ApplicationImpersonation role to an application in O365.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1098.002
    data_sources:
      - o365
      - o365
rules_count: 2
---

The ApplicationImpersonation role in Office 365 grants extensive privileges, allowing a user or application to impersonate any other user within the organization. Assignment of this role is a sensitive event that requires careful monitoring. This activity is significant because the ApplicationImpersonation role allows impersonation of any user, enabling access to and modification of their mailbox. Attackers, such as the NOBELIUM group, can abuse this role to gain unauthorized access to sensitive information, manipulate mailbox data, and perform actions as a legitimate user. The source detection logic leverages the Office 365 Management Activity API to monitor Azure Active Directory audit logs.

## Attack Chain

1.  Initial Access: An attacker gains initial access to an account with sufficient privileges to modify Office 365 roles.
2.  Privilege Escalation: The attacker attempts to assign the ApplicationImpersonation role to a compromised user account or a newly created service principal. This can be achieved via PowerShell or the Azure AD portal.
3.  Role Assignment: The "New-ManagementRoleAssignment" operation is executed within the Office 365 environment, assigning the ApplicationImpersonation role.
4.  Persistence: The attacker leverages the newly assigned ApplicationImpersonation role to maintain persistent access to the target organization's mailboxes.
5.  Data Access: The attacker uses the ApplicationImpersonation role to access and exfiltrate sensitive data from mailboxes.
6.  Lateral Movement: With access to user mailboxes, the attacker gathers information to facilitate lateral movement within the organization.
7.  Covering Tracks: The attacker may attempt to disable logging or remove audit trails to conceal their activities.

## Impact

Successful exploitation can lead to complete compromise of sensitive email data, intellectual property theft, and potential business email compromise (BEC) attacks. An attacker with the ApplicationImpersonation role can read, modify, and delete emails from any user's mailbox, leading to significant data breaches and reputational damage.

## Recommendation

*   Deploy the Sigma rule `O365 ApplicationImpersonation Role Assigned` to your SIEM and tune for your environment.
*   Review existing ApplicationImpersonation role assignments to identify and revoke any unauthorized or suspicious grants.
*   Monitor O365 management activity logs for unusual "New-ManagementRoleAssignment" events.
*   Investigate any alerts triggered by the detection logic, focusing on the `target_user` and `user` fields in the logs.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges.
*   Regularly audit Azure AD roles and permissions to ensure least privilege.
