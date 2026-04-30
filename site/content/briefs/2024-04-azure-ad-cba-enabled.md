---
title: Azure AD Certificate-Based Authentication Enabled
slug: 2024-04-azure-ad-cba-enabled
description: Enabling certificate-based authentication (CBA) in Azure Active Directory can be abused by attackers to establish persistence, escalate privileges, and impair defenses.
date: "2024-04-29T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - certificate-based-authentication
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://posts.specterops.io/passwordless-persistence-and-privilege-escalation-in-azure-98a01310be3f
  - https://goodworkaround.com/2022/02/15/digging-into-azure-ad-certificate-based-authentication/
rules:
  - title: Azure AD Certificate Based Authentication Enabled
    description: Detects when certificate based authentication has been enabled in an Azure Active Directory tenant.
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
  - title: Azure AD Certificate Authority Registration
    description: Detects when a new certificate authority is registered in Azure AD, potentially indicating malicious CBA setup.
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
rules_count: 2
---

Certificate-Based Authentication (CBA) in Azure Active Directory allows users and services to authenticate using digital certificates instead of passwords. While intended to enhance security, misconfiguration or malicious use of CBA can lead to significant security risks. Attackers can exploit CBA to gain unauthorized access, establish persistent footholds, and escalate privileges within the Azure environment. This involves manipulating authentication policies to favor or require certificate authentication, potentially bypassing other security controls. Detection of CBA enablement is crucial as it can be a precursor to more sophisticated attacks targeting cloud resources.

## Attack Chain

1. An attacker gains initial access to an Azure AD account with sufficient privileges to modify authentication policies (e.g., Global Administrator).
2. The attacker modifies the Azure AD authentication methods policy to enable certificate-based authentication.
3. The attacker registers a certificate authority (CA) in Azure AD, which will be used to issue certificates for authentication.
4. The attacker crafts or compromises a certificate that is trusted by the registered CA.
5. The attacker uses the crafted certificate to authenticate to Azure AD, bypassing traditional password-based authentication.
6. The attacker leverages the newly gained access to provision new resources, modify existing configurations, or access sensitive data.
7. The attacker establishes persistence by creating service principals or applications that authenticate using certificates, allowing them to maintain access even if the initial account is compromised.

## Impact

Successful exploitation of CBA can lead to full compromise of an Azure AD tenant. Attackers can gain access to sensitive data, disrupt services, and deploy malicious applications. The lack of multi-factor authentication on certificate-based logins significantly increases the risk of unauthorized access. The impact can range from data breaches and financial losses to complete operational shutdown, depending on the scope of the compromised resources.

## Recommendation

*   Deploy the Sigma rule to detect when certificate-based authentication is enabled in Azure AD (`Authentication Methods Policy Update` in Audit Logs).
*   Monitor Azure AD audit logs for modifications to authentication methods policies, paying close attention to changes related to certificate-based authentication.
*   Implement strong certificate management practices, including proper key storage, certificate revocation, and monitoring of certificate usage.
*   Investigate any unexpected changes to Azure AD authentication policies or the registration of new certificate authorities.
