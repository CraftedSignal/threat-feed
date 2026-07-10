---
title: Entra ID Service Principal Sign-in from Unusual ASN
slug: 2024-01-09-entra-id-service-principal-unusual-asn
description: Detection of Entra ID service principal sign-ins originating from a previously unseen combination of workload identity and source autonomous system number (ASN), potentially indicating compromised credentials or malicious activity.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra-id
  - service-principal
  - initial-access
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
  - https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identities
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
  - https://www.wiz.io/blog/lateral-movement-risks-in-the-cloud-and-how-to-prevent-them-part-3-from-compromis
rules:
  - title: Entra ID Service Principal Sign-in from Unusual ASN
    description: Detects Entra ID service principal sign-ins originating from a previously unseen ASN.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Service Principal Sign-in Success
    description: Detects successful Entra ID service principal sign-ins, which should be monitored for suspicious activity.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies unusual sign-in patterns for Entra ID service principals. The rule triggers when a service principal's sign-in originates from a source ASN that has not been observed in conjunction with that specific service principal within a defined history window. This behavior could indicate that an attacker has gained access to application secrets or tokens and is attempting to authenticate from an unfamiliar network, potentially preceding data access, lateral movement, or ransomware deployment within the tenant. The rule is designed to detect initial access attempts based on novel network paths for non-interactive workload identities. The rule focuses on first-seen network context, not proof of compromise by itself. It excludes Microsoft-labeled ASNs to reduce noise, but it is recommended that high-value investigations also review raw sign-in data for suspicious activity that only appears under those labels.

## Attack Chain

1.  **Credential Compromise:** An attacker gains unauthorized access to an Entra ID service principal's credentials (secrets, certificates, or tokens).
2.  **Initial Access:** The attacker uses the compromised credentials to attempt a sign-in to Entra ID as the service principal.
3.  **Authentication Request:** The attacker's request originates from a network with a previously unseen ASN for that specific service principal.
4.  **Sign-in Logging:** Entra ID logs the successful sign-in attempt, including the service principal ID, source IP address, and ASN.
5.  **Detection Trigger:** The detection rule analyzes the sign-in logs and identifies the unusual (service principal, ASN) combination.
6.  **Resource Access:** Upon successful authentication, the attacker attempts to access resources and services authorized for the service principal (e.g., Azure subscriptions, Key Vault, Microsoft Graph APIs).
7.  **Lateral Movement/Data Exfiltration:** The attacker leverages the compromised service principal to move laterally within the cloud environment, access sensitive data, or exfiltrate information.
8.  **Persistence/Privilege Escalation:** The attacker may attempt to establish persistence by creating new credentials or modifying the service principal's permissions to maintain long-term access and potentially elevate privileges.

## Impact

A successful attack leveraging compromised service principal credentials can lead to unauthorized access to sensitive data, lateral movement within the cloud environment, and potentially ransomware deployment. The number of potential victims depends on the scope of access granted to the compromised service principal. Industries heavily reliant on cloud services and automation are at higher risk. Failure to detect and respond to this type of attack can result in significant data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Entra ID Service Principal Sign-in from Unusual ASN` to your SIEM to detect unusual sign-in patterns. Tune the history window (`history_window_start`) to suit your environment and reduce false positives.
*   Investigate any alerts generated by the Sigma rule, focusing on the application associated with the service principal (`azure.signinlogs.properties.app_display_name`), the source ASN (`source.as.number`), and the actions taken after the sign-in event.
*   Review Entra audit logs for recent changes to the affected application, such as modifications to client secrets, certificates, federated credentials, owners, API permissions, or app role assignments.
*   Implement robust credential management practices for service principals, including regular rotation of secrets and certificates, and the use of managed identities where appropriate.
*   Implement Conditional Access policies for workload identities to restrict access based on network location, device posture, and other factors.
