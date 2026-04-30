---
title: Azure AD Root Certificate Authority Added for Passwordless Authentication
slug: 2024-05-azuread-root-ca-add
description: An attacker may add a new root certificate authority to an Azure AD tenant to support certificate-based authentication for persistence, privilege escalation, or defense evasion.
date: "2024-05-08T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.credential-access
  - attack.persistence
  - attack.privilege-escalation
  - attack.defense-impairment
  - attack.t1556
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f
  - https://goodworkaround.com/2022/02/15/digging-into-azure-ad-certificate-based-authentication/
rules:
  - title: New Root Certificate Authority Added
    description: Detects newly added root certificate authority to an AzureAD tenant to support certificate based authentication.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1556
    data_sources:
      - azure
      - auditlogs
  - title: AzureAD - Modified Company Information Object
    description: Detects modifications to the company information object in Azure AD. Attackers may modify this object to establish persistence or for other malicious purposes.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege-escalation
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

The addition of a new root certificate authority (CA) in Azure Active Directory (Azure AD) to support certificate-based authentication (CBA) can be a sign of malicious activity. While CBA offers passwordless authentication benefits, attackers can abuse it to establish persistent access, escalate privileges, or evade detection. An attacker with sufficient privileges in the Azure AD tenant can add a rogue CA, enabling them to authenticate as any user within the directory, even without their password. This bypasses multi-factor authentication (MFA) and grants unauthorized access to sensitive resources and data. Defenders should monitor Azure AD audit logs for unexpected modifications to the `TrustedCAsForPasswordlessAuth` setting, as this could indicate a compromised administrator account or an insider threat attempting to establish a backdoor.

## Attack Chain

1.  Compromise an Azure AD administrator account with sufficient privileges to modify tenant-wide settings. This may be achieved through phishing, credential stuffing, or exploiting vulnerabilities.
2.  The attacker authenticates to the Azure portal or uses PowerShell cmdlets to interact with Azure AD.
3.  The attacker executes commands to add a new, attacker-controlled root certificate authority to the `TrustedCAsForPasswordlessAuth` setting. This involves modifying the Company Information object.
4.  The attacker generates or obtains a certificate signed by the newly added root CA.
5.  The attacker uses the certificate to authenticate to Azure AD as a targeted user, bypassing password requirements and multi-factor authentication.
6.  The attacker gains access to the targeted user's resources, such as email, files, and applications.
7.  The attacker escalates privileges within the Azure AD tenant by impersonating highly privileged users or roles.
8.  The attacker maintains persistent access to the Azure AD tenant, even if the compromised administrator account is remediated.

## Impact

A successful attack can lead to complete compromise of the Azure AD tenant, including access to sensitive data, applications, and resources. Attackers can use the compromised tenant to move laterally to other systems, exfiltrate data, or disrupt business operations. The number of potential victims is dependent on the size of the Azure AD tenant. Organizations across all sectors are at risk, especially those heavily reliant on Azure AD for identity and access management.

## Recommendation

*   Deploy the Sigma rule "New Root Certificate Authority Added" to your SIEM to detect unauthorized modifications to the `TrustedCAsForPasswordlessAuth` setting (rule).
*   Review Azure AD audit logs regularly for suspicious activity related to the "Set Company Information" operation (logsource).
*   Implement multi-factor authentication (MFA) for all Azure AD accounts, including administrators, but understand that CBA can bypass it.
*   Enforce the principle of least privilege and restrict the number of accounts with permissions to modify tenant-wide settings.
*   Monitor for the use of certificates signed by unknown or untrusted CAs to authenticate to Azure AD.
*   Consult the SpecterOps and Goodworkaround articles for more information on certificate-based authentication abuse in Azure AD (references).
