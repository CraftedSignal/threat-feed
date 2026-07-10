---
title: Azure Front Door WAF Policy Deletion Detection
slug: 2024-01-azure-frontdoor-waf-deletion
description: Detection of Azure Front Door Web Application Firewall (WAF) policy deletion, which can indicate an attacker's attempt to evade defenses by removing a security layer protecting web applications.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - waf
  - defense_evasion
vendors:
  - Microsoft
products:
  - Azure Front Door WAF
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#networking
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/007/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Azure Front Door WAF Policy Deleted
    description: Detects the deletion of an Azure Front Door Web Application Firewall (WAF) policy.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Front Door WAF Policy Deletion Attempt Failed
    description: Detects failed attempts to delete an Azure Front Door Web Application Firewall (WAF) policy, which could indicate unauthorized access attempts or misconfigurations.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This threat brief focuses on the detection of unauthorized or malicious deletion of Azure Front Door Web Application Firewall (WAF) policies. Azure Front Door WAF policies are critical security controls that protect web applications by filtering and monitoring HTTP requests, blocking malicious traffic and preventing exploitation of vulnerabilities. An adversary may delete these policies to bypass security measures, facilitating unauthorized access, data exfiltration, or other malicious activities. The deletion of a WAF policy can have a significant impact, potentially exposing web applications to a wide range of attacks, including SQL injection, cross-site scripting (XSS), and other web-based threats. Defenders should monitor for unexpected deletions of these policies and promptly investigate any such events. This brief provides guidance for detection engineers to identify and respond to this type of defense evasion.

## Attack Chain

1.  **Initial Access:** The attacker gains access to an Azure account with sufficient privileges to manage Front Door WAF policies, possibly through compromised credentials or exploiting a privilege escalation vulnerability.
2.  **Discovery:** The attacker enumerates existing Front Door WAF policies to identify targets for disabling or deletion.
3.  **Defense Evasion:** The attacker initiates the deletion of a Front Door WAF policy using the Azure portal, Azure CLI, or PowerShell. The specific operation name is "MICROSOFT.NETWORK/FRONTDOORWEBAPPLICATIONFIREWALLPOLICIES/DELETE".
4.  **Persistence (Optional):** The attacker may attempt to prevent detection by disabling logging or other security monitoring features within Azure.
5.  **Impact:** With the WAF policy removed, web applications protected by the policy become vulnerable to a wide range of web-based attacks.
6.  **Further Exploitation:** The attacker leverages the unprotected web applications to gain unauthorized access to sensitive data, deploy malware, or perform other malicious activities.

## Impact

Successful deletion of a Front Door WAF policy can expose web applications to a variety of attacks, including SQL injection, cross-site scripting (XSS), and DDoS attacks. This can lead to data breaches, service disruptions, and reputational damage. The severity of the impact depends on the criticality of the protected applications and the sensitivity of the data they process.

## Recommendation

*   Deploy the Sigma rule `Azure Front Door WAF Policy Deleted` to your SIEM to detect unauthorized WAF policy deletions by monitoring Azure activity logs.
*   Enable Azure Activity Log monitoring and ensure logs are ingested into your SIEM to provide the data source for the detection rule.
*   Implement Role-Based Access Control (RBAC) with the principle of least privilege to restrict access to Azure management operations and minimize the risk of unauthorized policy modifications.
*   Investigate any identified WAF policy deletion events by examining the associated user identity and the context of the deletion, as described in the overview.
