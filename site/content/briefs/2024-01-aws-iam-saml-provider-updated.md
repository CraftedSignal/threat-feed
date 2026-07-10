---
title: AWS IAM SAML Provider Updated Detection
slug: 2024-01-aws-iam-saml-provider-updated
description: Detection of unauthorized updates to AWS IAM SAML providers, potentially leading to privilege escalation and persistent access via trust manipulation.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - iam
  - saml
  - privilege-escalation
  - defense-evasion
vendors:
  - AWS
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
references:
  - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
  - https://attack.mitre.org/techniques/T1484/
  - https://attack.mitre.org/techniques/T1484/002/
rules:
  - title: AWS IAM SAML Provider Updated (Non-SSO)
    description: Detects updates to AWS IAM SAML providers originating from outside of AWS SSO, potentially indicating unauthorized trust modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1484
      - T1484.002
    data_sources:
      - cloudtrail
      - aws
  - title: AWS IAM SAML Provider Metadata Modified
    description: Detects modifications to the SAML metadata document of an AWS IAM SAML provider.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1484
      - T1484.002
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on detecting unauthorized modifications to AWS IAM SAML providers. SAML providers manage federated authentication between AWS and external identity providers (IdPs). Attackers with sufficient privileges can alter a SAML provider's metadata or certificate to redirect authentication flows, facilitate unauthorized federation, or escalate privileges by manipulating identity trust relationships. The risk lies in the potential for persistent or covert access, even after credential revocation, due to the SAML provider's role in single sign-on (SSO) access for users and applications. The detection strategy focuses on identifying `UpdateSAMLProvider` API calls that deviate from standard AWS Single Sign-On (SSO) operations, as these updates can drastically impact account-wide federated authentication.

## Attack Chain

1.  **Initial Access:** An attacker gains administrative access to the AWS account, potentially through compromised credentials or an insider threat.
2.  **Discovery:** The attacker identifies existing IAM SAML providers within the AWS environment.
3.  **Trust Modification:** The attacker uses the `UpdateSAMLProvider` API call to modify the SAML provider's metadata or certificate. This could involve replacing the valid certificate with a self-signed or attacker-controlled certificate, or modifying the SAML metadata document to point to a malicious IdP.
4.  **Redirection of Authentication Flow:** Users attempting to authenticate via the federated SSO are now redirected to the attacker's malicious IdP or presented with a certificate validation error, potentially leading to credential harvesting or other malicious activity.
5.  **Privilege Escalation:** If the attacker controls the malicious IdP, they can issue SAML assertions that grant them elevated privileges within the AWS environment, potentially assuming roles with broader access than authorized.
6.  **Persistence:** The attacker maintains persistent access to the AWS environment through the modified SAML provider, even if the original compromised credentials are revoked.
7.  **Lateral Movement/Data Exfiltration:** Leveraging the escalated privileges, the attacker can move laterally within the AWS environment, accessing sensitive data or resources, and potentially exfiltrating data to an external location.

## Impact

A successful attack on an AWS IAM SAML provider can have significant consequences, potentially affecting all federated users and applications within the AWS account. This can lead to unauthorized access to sensitive data, service disruption, and privilege escalation across the organization's cloud infrastructure. The impact can range from data breaches and financial losses to reputational damage and compliance violations. The scope depends on the roles associated with the SAML provider and the extent of the attacker's lateral movement within the compromised AWS environment.

## Recommendation

*   Deploy the Sigma rule "AWS IAM SAML Provider Updated (Non-SSO)" to your SIEM to detect unauthorized updates to SAML providers based on CloudTrail logs.
*   Enable AWS Config to monitor and record SAML provider resource configuration history to facilitate investigation and rollback (reference: Overview).
*   Implement strict IAM policies to limit permissions for modifying SAML providers (`iam:UpdateSAMLProvider`) to dedicated identity management roles (reference: Overview).
*   Review CloudTrail logs for related IAM configuration changes, including `CreateRole`, `AttachRolePolicy`, or `UpdateAssumeRolePolicy` events following a detected `UpdateSAMLProvider` event (reference: Overview).
*   Coordinate with the identity management team to confirm the legitimacy of any SAML provider updates and ensure they align with planned IdP maintenance or certificate rotation (reference: Overview).
