---
title: Entra ID External Guest User Invitation
slug: 2024-01-entra-guest-invite
description: Detection of external guest user invitations in Entra ID, which can be abused for unauthorized access and persistence by creating overlooked accounts.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - azure
  - initial-access
  - persistence
vendors:
  - Microsoft
products:
  - Entra ID
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://docs.microsoft.com/en-us/azure/governance/policy/samples/cis-azure-1-1-0
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/techniques/T1136/
  - https://attack.mitre.org/techniques/T1136/003/
rules:
  - title: Entra ID External Guest User Invited
    description: Detects invitations to external guest users in Entra ID, which could indicate unauthorized account creation.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - audit
      - azure
  - title: Entra ID External Guest User Invited (Failed Attempt)
    description: Detects failed attempts to invite external guest users in Entra ID, which could indicate reconnaissance.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - audit
      - azure
rules_count: 2
---

This detection identifies when an external guest user is invited within an Entra ID (Azure Active Directory) environment. Entra ID's collaboration features enable inviting external users as guests, but malicious actors can exploit this to gain unauthorized access. The creation of unnecessary guest accounts can easily be overlooked, creating a potential vulnerability for initial access and persistence. This activity is detected by monitoring Azure audit logs for successful "Invite external user" operations where the target resource display name is "guest." The detection rule is designed to alert on unexpected or unauthorized guest account creations within the cloud environment.

## Attack Chain

1. An attacker gains initial access to an Entra ID user account, possibly through compromised credentials (T1078).
2. The attacker leverages the compromised account to access the Azure portal or uses PowerShell/CLI to interact with Entra ID.
3. The attacker initiates the "Invite external user" operation within Entra ID.
4. A new guest user account is created in Entra ID (T1136.003).
5. Permissions are assigned to the guest user, potentially granting access to sensitive resources.
6. The guest user account is used to access resources within the Entra ID environment.
7. The attacker may then use the guest account for lateral movement within the cloud environment.

## Impact

Successful exploitation could lead to unauthorized access to sensitive resources within the Entra ID environment. Overlooked guest accounts can persist indefinitely, providing a backdoor for attackers. The risk score for this activity is rated as 21 (on a scale that is not defined in the provided source), and the severity is low, suggesting a potential but not immediate threat if promptly addressed. Organizations using Azure AD may be vulnerable if guest user creation is not strictly controlled and monitored.

## Recommendation

*   Deploy the Sigma rule "Entra ID External Guest User Invited" to your SIEM and tune for your environment.
*   Review Azure AD audit logs for the "Invite external user" operation and validate the legitimacy of each invitation.
*   Implement conditional access policies to restrict guest user invitations to authorized personnel only.
*   Enhance monitoring and alerting for guest user invitations by integrating with a SIEM system to ensure timely detection and response.
