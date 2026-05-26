---
title: CVE-2026-35430 — Azure PIM Authorization Bypass via User-Controlled Key
slug: 2026-05-azure-pim-auth-bypass
description: CVE-2026-35430 allows an authorized attacker to elevate privileges over a network in Azure Privileged Identity Management (PIM) through a user-controlled key.
date: "2026-05-26T13:33:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege escalation
  - azure
vendors:
  - Microsoft
products:
  - Azure Privileged Identity Management (PIM)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
cves:
  - id: CVE-2026-35430
    cvss: 8.8
    epss: 0.00057
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35430
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-35430
rules:
  - title: Detect CVE-2026-35430 Exploitation Attempt - Azure PIM Role Activation with Suspicious Key Modification
    description: Detects attempts to activate privileged roles in Azure PIM after a suspicious modification of user-controlled keys, potentially indicating CVE-2026-35430 exploitation.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-35430
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
  - title: Detect CVE-2026-35430 - Anomalous Azure AD Authentication Context Modification
    description: Detects modifications to Azure AD authentication contexts, which might indicate an attempt to exploit CVE-2026-35430 by manipulating user-controlled keys.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-35430
      - privilege_escalation
    techniques:
      - T1556.006
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

CVE-2026-35430 is an authorization bypass vulnerability affecting Azure Privileged Identity Management (PIM). An authorized attacker can exploit this vulnerability to elevate privileges over a network. This is achieved by manipulating a user-controlled key within the PIM system, leading to unauthorized access and control. This vulnerability poses a significant risk to organizations relying on Azure PIM for managing privileged access, potentially allowing attackers to compromise critical resources and data. The vulnerability was reported to Microsoft and assigned a CVSS v3.1 score of 8.8, indicating a high severity. Defenders should prioritize patching and monitoring for any suspicious activity related to PIM.

## Attack Chain

1. An attacker gains initial access to an Azure account with some level of authorization.
2. The attacker identifies the Azure PIM service as a potential target for privilege escalation.
3. The attacker discovers a user-controlled key within the Azure PIM configuration.
4. The attacker modifies the user-controlled key to bypass authorization checks.
5. The attacker attempts to activate a privileged role within Azure PIM.
6. Due to the manipulated key, the attacker is granted the privileged role despite lacking proper authorization.
7. The attacker uses the elevated privileges to access and control network resources.

## Impact

Successful exploitation of CVE-2026-35430 allows an attacker to gain unauthorized privileged access within an Azure environment. This can lead to a complete compromise of the targeted network, including access to sensitive data, modification of critical configurations, and disruption of services. The impact is significant for organizations relying on Azure PIM to protect their infrastructure and data, potentially leading to substantial financial and reputational damage.

## Recommendation

*   Apply the patch provided by Microsoft for CVE-2026-35430 as soon as possible to prevent exploitation.
*   Monitor Azure logs for any unauthorized attempts to activate privileged roles in PIM, using the provided Sigma rules.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with privileged access, to reduce the risk of initial access.
