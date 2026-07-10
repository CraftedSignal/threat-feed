---
title: Azure AD Tenant Wide Admin Consent Granted
slug: 2024-01-03-azure-ad-admin-consent
description: Detection of admin consent granted to an application within an Azure AD tenant which could lead to data exfiltration and persistence.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - NOBELIUM Group
tags:
  - azure
  - persistence
  - cloud
vendors:
  - Microsoft
products:
  - Azure AD
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://attack.mitre.org/techniques/T1098/003/
  - https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452
  - https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent
  - https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent?pivots=portal
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT501/AZT501-2/
rules:
  - title: Azure AD Tenant Wide Admin Consent Granted
    description: Detects when an admin consent is granted to an application for the entire Azure AD tenant
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - dns_query
      - windows
  - title: Azure AD Admin Consent via Modified Properties
    description: Detects admin consent based on modified properties in Azure AD audit logs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This analytic identifies instances where admin consent is granted to an application within an Azure AD tenant. It leverages Azure AD audit logs, specifically events related to the admin consent action within the ApplicationManagement category, and utilizes the `azure:monitor:aad` sourcetype. This activity is significant because admin consent allows applications to access data across the entire tenant, potentially exposing vast amounts of organizational data. The detection is sourced from Splunk's ES Content and adapted for broader use. Successfully gaining admin consent can grant attackers persistent access and control over the Azure AD environment.

## Attack Chain

1. An attacker compromises an administrator account through phishing or credential stuffing.
2. The attacker logs into the Azure portal using the compromised administrator credentials.
3. The attacker navigates to the Azure Active Directory section.
4. The attacker registers a malicious application or uses an existing compromised application.
5. The attacker requests tenant-wide admin consent for the malicious application. This often involves tricking the administrator into approving the request.
6. The administrator grants consent, either unknowingly or due to social engineering.
7. The malicious application gains access to data across the entire tenant based on the granted permissions.
8. The attacker uses the application's permissions to exfiltrate sensitive data, establish persistence, or perform other malicious actions.

## Impact

Successful exploitation allows attackers to gain extensive and persistent access to sensitive data within the Azure AD tenant. This can lead to data exfiltration, espionage, further malicious activities, and potential compliance violations. The impact spans across all applications and data within the tenant that the application has been granted access to. Lateral movement becomes trivial, and the attacker can establish a strong foothold within the cloud environment.

## Recommendation

*   Deploy the Sigma rule "Azure AD Tenant Wide Admin Consent Granted" to your SIEM and tune for your environment.
*   Investigate any instances of admin consent being granted, especially if the application is unfamiliar or the request seems suspicious. Reference the detection results by using the provided drilldown searches.
*   Implement multi-factor authentication (MFA) for all administrator accounts to mitigate the risk of compromised credentials.
*   Regularly review and audit application permissions within Azure AD to identify and remove any unnecessary or overly permissive consents.
*   Monitor Azure AD audit logs for unusual activity, such as unexpected application registrations or consent requests. Enable `azure:monitor:aad` sourcetype and Auditlogs log category.
