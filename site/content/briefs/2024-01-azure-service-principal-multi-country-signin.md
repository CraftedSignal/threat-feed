---
title: Azure Service Principal Authentication from Multiple Countries
slug: 2024-01-azure-service-principal-multi-country-signin
description: Detects Azure service principals authenticating from multiple countries within a short time, indicating potentially compromised credentials being used from different geographic locations.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - azure
  - service principal
  - initial access
  - credential compromise
vendors:
  - Microsoft
products:
  - Azure
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identities
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
  - https://www.wiz.io/blog/lateral-movement-risks-in-the-cloud-and-how-to-prevent-them-part-3-from-compromis
rules:
  - title: Azure Service Principal Authentication from Multiple Countries
    description: Detects when an Azure service principal authenticates from multiple countries within a short time window, potentially indicating compromised credentials.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Azure Service Principal Sign-in from Multiple Cities
    description: Detects when an Azure service principal authenticates from multiple cities within a short time window, suggesting compromised credentials.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies instances where Azure service principals authenticate from multiple countries within a one-hour window. Service principals, designed for non-interactive automation and application access, typically authenticate from consistent locations tied to their deployment infrastructure. Unusual authentication patterns, especially from disparate geographic regions, suggest credential compromise, such as stolen credentials, phished service principal secrets, or compromised automation accounts. This activity may indicate an attacker attempting to gain unauthorized access to cloud resources by leveraging a valid, but compromised, service principal. The references include examples of threat actors using stolen cloud credentials to perform lateral movement and deploy ransomware.

## Attack Chain

1.  Attacker gains initial access to service principal credentials through phishing, credential stuffing, or other means.
2.  Attacker uses the stolen credentials to authenticate to Azure Active Directory.
3.  Attacker establishes connections from multiple distinct geographic locations, potentially using VPNs or proxies to mask their true location.
4.  The service principal successfully authenticates due to the valid credentials.
5.  Attacker leverages the service principal's assigned roles and permissions to access resources within the Azure environment. This may include storage accounts, virtual machines, or databases.
6.  Attacker performs reconnaissance to identify valuable data and services.
7.  Attacker exfiltrates sensitive data or deploys malicious workloads, such as ransomware, to disrupt services and demand ransom payments.

## Impact

Compromised service principal credentials can lead to unauthorized access to sensitive data, service disruption, and potential financial loss. Successful attacks may result in data breaches, ransomware deployment, and significant damage to an organization's reputation. While the specific number of victims is unknown, similar cloud-based attacks have affected organizations across various sectors.

## Recommendation

*   Deploy the Sigma rule `Azure Service Principal Authentication from Multiple Countries` to your SIEM to detect suspicious multi-country sign-ins (see `rules` section).
*   Review Azure AD Audit Logs for recent changes to service principals, such as new credentials or owner changes, as described in the investigation steps.
*   Rotate service principal credentials immediately upon detection of suspicious activity and revoke active sessions as recommended in the investigation guide.
*   Implement Conditional Access policies to restrict service principal authentication by location, when supported, as outlined in the response and remediation guidance.
*   Baseline the expected geographic distribution for each service principal as mentioned in the false positives analysis to reduce false positives.
