---
title: Azure AD Service Principal Owner Added
slug: 2024-01-02-azure-ad-service-principal-owner-added
description: Detection of a new owner being added to an Azure AD Service Principal, potentially indicating persistence or privilege escalation by an attacker exploiting the lack of multi-factor authentication on service principals.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - NOBELIUM Group
tags:
  - azure
  - cloud
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://attack.mitre.org/techniques/T1098/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_service_principal_owner_added.yml
rules:
  - title: Azure AD Service Principal Owner Added
    description: Detects the addition of a new owner to a Service Principal within an Azure AD tenant, which could indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - audit
      - azure
  - title: Azure AD Service Principal Owner Added - Cross User
    description: Detects when a different user adds a new owner to a Service Principal within an Azure AD tenant, which could indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - audit
      - azure
rules_count: 2
---

This analytic detects the addition of a new owner to a Service Principal within an Azure AD tenant. Service Principals are often targeted by attackers due to their lack of multi-factor authentication (MFA) and conditional access support. The detection leverages Azure Active Directory events from the AuditLog log category, specifically monitoring the "Add owner to application" operation. This activity is a significant indicator of potential persistence or privilege escalation, as a compromised Service Principal can grant unauthorized access to critical Azure AD resources. A successful attack using this technique could allow attackers to maintain access to the Azure AD environment with only single-factor authentication, bypassing typical security controls. This detection is based on analysis of activity patterns associated with the NOBELIUM group.

## Attack Chain

1.  The attacker compromises an initial user account or service principal through credential theft or other means (e.g., phishing).
2.  The attacker leverages the compromised account to enumerate existing Service Principals within the Azure AD tenant.
3.  The attacker identifies a target Service Principal with elevated permissions or access to critical resources.
4.  The attacker executes the "Add owner to application" operation, adding a new owner (controlled by the attacker) to the target Service Principal. This operation is logged in Azure AD Audit Logs.
5.  The newly added owner account (controlled by the attacker) now has control over the Service Principal.
6.  The attacker uses the compromised Service Principal to access resources and data within the Azure AD environment, bypassing MFA and conditional access controls.
7.  The attacker moves laterally within the cloud environment, compromising other services and resources.
8.  The attacker achieves their final objective, which may include data exfiltration, system disruption, or further privilege escalation.

## Impact

A successful attack leveraging Service Principal owner addition can result in significant damage. Attackers can gain persistent access to the Azure AD environment, bypassing MFA and conditional access. This can lead to unauthorized access to sensitive data, compromise of critical cloud resources, and potential disruption of business operations. Due to the nature of cloud environments, a single compromised Service Principal can grant access to a wide range of services and data, impacting numerous users and applications.

## Recommendation

*   Deploy the Sigma rule `Azure AD Service Principal Owner Added` to your SIEM and tune for your environment to detect the addition of new owners to Service Principals based on Azure AD Audit Logs.
*   Investigate any detected instances of Service Principal owner additions for potentially malicious activity, focusing on the `initiatedBy` and `newOwner` fields in the logs.
*   Implement strict controls and monitoring around Service Principal creation and management.
*   Review and reduce the number of Service Principals with excessive privileges.
*   Investigate related `Azure Active Directory Persistence` and `Azure Active Directory Privilege Escalation` analytic stories after detecting this activity.
