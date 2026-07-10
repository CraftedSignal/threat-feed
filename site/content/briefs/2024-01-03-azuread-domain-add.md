---
title: Azure AD Custom Domain Addition for Persistence
slug: 2024-01-03-azuread-domain-add
description: Detection of a new custom domain addition in Azure AD audit logs, potentially indicating an attacker establishing persistence via identity federation backdoors for unauthorized access and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - persistence
  - cloud
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1484
    technique_name: Domain Trust Discovery
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/domains-manage
  - https://www.mandiant.com/resources/remediation-and-hardening-strategies-microsoft-365-defend-against-apt29-v13
  - https://o365blog.com/post/federation-vulnerability/
  - https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html
  - https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors
  - https://attack.mitre.org/techniques/T1484/002/
rules:
  - title: Azure AD New Custom Domain Added
    description: Detects the addition of a new custom domain in Azure AD, which may indicate malicious persistence attempts.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1484.002
    data_sources:
      - audit
      - azure
  - title: Azure AD Domain Additions by New Users
    description: Detects Azure AD domain additions performed by users who have recently appeared in logs, potentially indicating compromised accounts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1484.002
    data_sources:
      - audit
      - azure
rules_count: 2
---

The addition of a new custom domain in Azure Active Directory (AD) can be a critical indicator of malicious activity. Attackers may add unverified domains to establish persistence through identity federation backdoors. This allows them to impersonate legitimate users, bypass multi-factor authentication, and maintain a foothold within the Azure AD environment. This technique is particularly relevant in scenarios where an attacker has already gained initial access and is looking to deepen their presence and control within the organization's cloud infrastructure. The activity is detected by monitoring Azure AD AuditLogs for successful "Add unverified domain" operations. Defenders should be aware of this technique to quickly identify and remediate unauthorized domain additions that could lead to significant security breaches. The references highlight APT29 as a potential actor abusing this technique.

## Attack Chain

1.  **Initial Compromise:** The attacker gains initial access to an Azure AD account through credential phishing, brute-force attacks, or exploiting a vulnerability.
2.  **Privilege Escalation:** The attacker escalates privileges within the compromised Azure AD account, potentially using techniques like exploiting misconfigured roles or permissions.
3.  **Domain Discovery:** The attacker enumerates existing domains within the Azure AD tenant to understand the current configuration.
4.  **Add Unverified Domain:** The attacker adds a new, unverified custom domain to the Azure AD tenant using the "Add unverified domain" operation.
5.  **Identity Federation Setup:** The attacker configures identity federation between the newly added domain and the Azure AD tenant to establish a backdoor.
6.  **Account Impersonation:** The attacker impersonates legitimate users within the Azure AD environment, leveraging the newly established federation.
7.  **Data Access and Exfiltration:** The attacker gains unauthorized access to sensitive data and exfiltrates it from the Azure AD environment.
8.  **Persistence:** The attacker maintains long-term access to the environment through the federated domain, even if initial access is revoked.

## Impact

Successful addition of a malicious custom domain can have severe consequences, including unauthorized access to sensitive data, privilege escalation, and long-term persistence within the Azure AD environment. This can lead to significant data breaches, financial losses, and reputational damage. Organizations in various sectors, including government, finance, and healthcare, are potential targets. If left undetected, attackers can maintain access for extended periods, potentially exfiltrating large volumes of sensitive data. Mandiant has documented real-world cases of APT29 using this technique.

## Recommendation

*   Deploy the Sigma rule `Azure AD New Custom Domain Added` to your SIEM and tune for your environment to detect unauthorized domain additions using `operationName="Add unverified domain"` and `properties.result=success`.
*   Enable and monitor Azure AD AuditLogs for all domain-related activities, focusing on "Add unverified domain" operations as described in the `data_source` field.
*   Review and restrict Azure AD roles and permissions to minimize the attack surface for privilege escalation, preventing attackers from adding new domains.
*   Investigate any alerts triggered by the Sigma rule by reviewing the `dest`, `user`, `src`, `vendor_account`, `vendor_product`, `user_agent`, `domain`, and `signature` fields in the logs.
*   Regularly review and validate all configured custom domains in Azure AD to identify and remove any unauthorized or suspicious domains as referenced in [https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/domains-manage](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/domains-manage).
