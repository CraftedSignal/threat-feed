---
title: Microsoft Entra ID Guest Account Promoted to Member
slug: 2026-06-entra-id-guest-to-member
description: A sophisticated threat actor, having compromised an existing guest account in Microsoft Entra ID, can establish persistent access and elevate privileges by performing a Guest-to-Member account conversion, which grants full directory read access and bypasses Conditional Access restrictions, enabling stealthy long-term access and reconnaissance.
date: "2026-06-18T15:40:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - persistence
  - azure
  - microsoft-entra-id
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/entra/external-id/user-properties
  - https://learn.microsoft.com/en-us/entra/identity/users/convert-external-users-internal
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_id_guest_account_promoted_to_member.toml
rules:
  - title: Detect Entra ID Guest Account Promoted to Member
    description: Identifies Microsoft Entra ID user accounts converted from Guest to Member type via an 'Update user' operation. This conversion removes external-identity Conditional Access restrictions and grants full directory read access, which can be leveraged by attackers for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - audit
      - azure
rules_count: 1
---

A sophisticated threat actor, having already established initial access to an organization's Microsoft Entra ID tenant through the compromise of a guest account, can achieve persistent access and elevate privileges by converting the compromised guest account to a member account. This high-impact technique, observed in campaigns targeting cloud environments, leverages the "Update user" operation to modify the `UserType` attribute. By changing an account from 'Guest' to 'Member', attackers gain full directory read access, bypass external-identity Conditional Access policies, and make the account appear as a standard internal employee, effectively masking their continued presence. This method of persistence is particularly insidious as it often avoids detection mechanisms designed for explicit role assignments, offering a stealthier way to maintain control and facilitate further malicious activities such as reconnaissance and data exfiltration. Defenders must monitor for these specific user attribute changes to detect such advanced persistence.

## Attack Chain

1.  **Initial Access**: An attacker compromises an existing legitimate guest account within an Entra ID tenant, typically through methods like phishing, credential stuffing, or supply chain compromise targeting an external partner.
2.  **Privilege Escalation/Compromise**: The attacker subsequently compromises an administrator account or gains sufficient permissions within the Entra ID tenant to modify user properties.
3.  **UserType Modification**: Using the compromised administrative privileges, the attacker executes an "Update user" operation within Entra ID, specifically targeting the previously compromised guest account.
4.  **Property Update**: During this "Update user" operation, the `UserType` attribute of the guest account is changed from `Guest` to `Member`.
5.  **Enhanced Permissions**: This conversion automatically grants the now-modified account full directory read access, which is typically restricted for external guest accounts.
6.  **Conditional Access Bypass**: The conversion also removes external-identity-specific Conditional Access restrictions, allowing the account to operate with fewer security constraints.
7.  **Stealthy Persistence**: The newly converted "Member" account is virtually indistinguishable from a standard internal employee account, establishing persistent access that often bypasses detection mechanisms for explicit role assignments.
8.  **Post-Exploitation**: The attacker leverages the "Member" account for broader reconnaissance, directory enumeration (e.g., via Graph API `/users`, `/groups`, `/applications`), data exfiltration, or further lateral movement within the organization's cloud environment.

## Impact

Successful exploitation results in an attacker maintaining stealthy, persistent access to the victim organization's Microsoft Entra ID environment. The compromised account gains full directory read access, enabling extensive reconnaissance and mapping of cloud resources and user identities. Furthermore, the bypass of external-identity Conditional Access policies allows the attacker to operate with fewer restrictions, potentially facilitating data exfiltration, further privilege escalation, and lateral movement into integrated cloud applications. This technique leads to long-term compromise, making detection and remediation challenging as the account appears benign.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Ensure comprehensive logging for `azure.auditlogs` events is enabled and ingested into your security monitoring platform.
*   Investigate all `Update user` operations where `UserType` changes from `Guest` to `Member` by examining the `initiated_by` field for authorization.
*   Proactively review `azure.signinlogs.*` for any directory enumeration patterns (e.g., access to Graph API `/users`, `/groups`, `/applications`) originating from recently converted accounts.
*   Implement strict change management processes for all B2B collaboration migrations or organizational restructuring that involves legitimate Guest-to-Member conversions, ensuring proper documentation and approval.
