---
title: Entra ID Service Principal Sign-in from Unusual Source ASN
slug: 2024-01-entra-id-service-principal-unusual-asn
description: Detects Entra ID service principal sign-ins from a source ASN that is unusual based on a history window, potentially indicating compromised credentials or a rogue application.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra_id
  - service_principal
  - initial_access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
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
    description: Detects Entra ID service principal sign-ins from a previously unseen ASN.
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
    description: Detects successful Entra ID service principal sign-ins
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies potentially malicious activity within Microsoft Entra ID (formerly Azure AD) by monitoring service principal sign-ins. Specifically, it flags instances where a service principal authenticates from an autonomous system number (ASN) that is not typically associated with that principal within a defined history window (10 days). Attackers compromising service principal credentials or application secrets may attempt to authenticate from unfamiliar networks, such as hosting providers, VPNs, or residential IPs, to gain initial access, move laterally, or deploy ransomware within the tenant. The rule focuses on identifying new network paths for non-interactive workload identities, improving the chances of catching malicious activity early in the attack chain. This detection is based on the Elastic detection rule released on 2026/04/06.

## Attack Chain

1.  The attacker gains unauthorized access to service principal credentials or application secrets.
2.  The attacker uses the compromised credentials to attempt authentication to Entra ID.
3.  The authentication request originates from an unusual ASN not previously associated with the service principal.
4.  Entra ID processes the authentication request and, if successful based on existing policies, grants access.
5.  The service principal, now under attacker control, performs actions based on its assigned permissions. This could include accessing sensitive data, modifying configurations, or escalating privileges.
6.  The attacker leverages the compromised service principal to move laterally within the cloud environment, accessing other resources or identities.
7.  The attacker may exfiltrate sensitive data or deploy malicious applications or scripts.
8.  The attacker may deploy ransomware targeting cloud resources.

## Impact

A successful attack leveraging compromised service principal credentials can result in significant damage, including data breaches, service disruptions, and financial losses. The potential impact extends to any resources accessible by the compromised service principal, potentially affecting critical business applications and data. If undetected, this activity can lead to full tenant compromise and significant remediation costs. Lateral movement and privilege escalation can further amplify the impact, affecting more resources and data within the environment.

## Recommendation

*   Deploy the Sigma rule `Entra ID Service Principal Sign-in from Unusual ASN` to your SIEM, ensuring it is tuned to exclude known benign ASNs for your service principals.
*   Review sign-in logs for successful authentications by service principals originating from unfamiliar ASNs as per the investigation guide provided in the rule description.
*   Implement conditional access policies to restrict service principal sign-ins to specific networks or locations.
*   Rotate application secrets and certificates for any service principal triggering the `Entra ID Service Principal Sign-in from Unusual ASN` detection.
*   Monitor Entra ID audit logs for changes to application permissions, client secrets, or ownership, especially before a suspicious sign-in, as described in the rule's triage steps.
*   Enrich `source.ip` addresses from alerts with threat intelligence data to identify residential or low-reputation ASNs, warranting increased scrutiny.
