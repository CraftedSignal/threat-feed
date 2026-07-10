---
title: O365 Cross-Tenant Access Policy Changes
slug: 2024-01-02-o365-cross-tenant-access-change
description: Adversaries modify Azure Active Directory cross-tenant access policies for lateral movement or persistence within compromised Microsoft 365 environments.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - office365
  - cross-tenant
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484
    technique_name: Domain Policy Modification
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://attack.mitre.org/techniques/T1484/002/
  - https://thehackernews.com/2023/08/emerging-attacker-exploit-microsoft.html
  - https://cyberaffairs.com/news/emerging-attacker-exploit-microsoft-cross-tenant-synchronization/
  - https://www.crowdstrike.com/blog/crowdstrike-defends-against-azure-cross-tenant-synchronization-attacks/
rules:
  - title: O365 Cross-Tenant Access Policy Change Detected
    description: Detects changes to cross-tenant access policies in Azure Active Directory.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - persistence
    techniques:
      - T1484.002
    data_sources:
      - office_365
      - o365
  - title: O365 Cross-Tenant Access Policy Modified by Uncommon User
    description: Detects changes to cross-tenant access policies by users who rarely modify these settings.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - persistence
    techniques:
      - T1484.002
    data_sources:
      - office_365
      - o365
rules_count: 2
---

Attackers are increasingly targeting Microsoft 365 environments, including Azure Active Directory, to establish persistence and facilitate lateral movement. A key technique involves manipulating cross-tenant access policies. These policies govern how an organization trusts and interacts with external Azure Active Directory tenants. By modifying these policies, attackers can grant themselves unauthorized access to resources, synchronize user accounts for long-term access, and bypass multi-factor authentication (MFA) controls. This activity can be difficult to detect due to the legitimate use of cross-tenant access for business collaboration. This type of attack was observed in August 2023, and impacts any organization using Azure AD cross-tenant access features.

## Attack Chain

1.  The attacker gains initial access to a privileged account within the target Azure Active Directory tenant, possibly via credential phishing or password spraying.
2.  The attacker authenticates to the Azure portal or uses PowerShell modules to interact with Azure Active Directory.
3.  The attacker identifies existing cross-tenant access policies configured within the target tenant.
4.  The attacker modifies an existing cross-tenant access policy or creates a new one to establish a trust relationship with an attacker-controlled Azure Active Directory tenant.
5.  The attacker configures the cross-tenant access policy to allow specific actions, such as user synchronization or application access, from the attacker-controlled tenant.
6.  The attacker synchronizes user accounts from the attacker-controlled tenant into the target tenant, granting themselves persistent access.
7.  The attacker uses the synchronized accounts to access sensitive resources and perform lateral movement within the target environment.

## Impact

Successful manipulation of cross-tenant access policies can lead to significant damage. Attackers can gain persistent, unauthorized access to sensitive data, applications, and infrastructure within the victim's Microsoft 365 environment. This may lead to data exfiltration, financial fraud, or disruption of business operations. The CrowdStrike blog post referenced in the source material highlights real-world instances of these attacks, and it should be considered a critical threat to organizations relying on cross-tenant access configurations.

## Recommendation

*   Deploy the provided Sigma rule `O365 Cross-Tenant Access Policy Change Detected` to your SIEM to detect unauthorized changes to cross-tenant access policies using Office 365 management activity logs.
*   Review existing cross-tenant access policies for unexpected or overly permissive configurations.
*   Implement multi-factor authentication (MFA) for all user accounts, including privileged accounts, to reduce the risk of initial compromise.
*   Monitor Azure Active Directory audit logs for suspicious activity related to cross-tenant access policy management.
*   Regularly audit and review permissions associated with synchronized accounts to identify and remediate any excessive privileges.
