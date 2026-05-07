---
title: CVE-2026-40379 Microsoft Enterprise Security Token Service (ESTS) Spoofing Vulnerability
slug: 2024-01-23-ests-spoofing
description: CVE-2026-40379 is a spoofing vulnerability in Microsoft Enterprise Security Token Service (ESTS) where exposure of sensitive information in Azure Entra ID allows an unauthorized attacker to perform spoofing over a network.
date: "2026-05-07T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - entra_id
  - spoofing
  - cloud
vendors:
  - Microsoft
products:
  - Enterprise Security Token Service
  - Azure Entra ID
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-40379
rules:
  - title: Detect CVE-2026-40379 Exploitation - Suspicious Token Issuance
    description: Detects CVE-2026-40379 exploitation — Suspicious token issuance events in Azure Entra ID logs, potentially indicating spoofing attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1550.002
    data_sources:
      - cloudtrail
      - azure
  - title: Detect CVE-2026-40379 Exploitation - Suspicious Token Usage
    description: Detects CVE-2026-40379 exploitation — Suspicious usage of tokens associated with the Enterprise Security Token Service in Azure Entra ID logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1550.002
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

CVE-2026-40379, disclosed on May 7, 2026, describes a spoofing vulnerability within the Microsoft Enterprise Security Token Service (ESTS) related to Azure Entra ID. This vulnerability can lead to the exposure of sensitive information to unauthorized actors, potentially allowing them to perform spoofing attacks over a network. The vulnerability lies within the ESTS component, and successful exploitation could allow an attacker to impersonate legitimate users or services within the Azure Entra ID environment. Defenders need to ensure proper configuration and monitoring of their Azure Entra ID environments to mitigate the risk posed by this vulnerability.

## Attack Chain

1. An attacker identifies a vulnerable ESTS configuration within an Azure Entra ID environment.
2. The attacker exploits CVE-2026-40379 to gain unauthorized access to sensitive information related to ESTS.
3. The exposed information is used to craft malicious security tokens.
4. The attacker uses the spoofed tokens to authenticate to other services within the Azure Entra ID environment.
5. The attacker gains access to resources and data that they are not authorized to access.
6. The attacker performs actions impersonating a legitimate user or service.
7. The attacker may escalate privileges within the Azure Entra ID environment.

## Impact

Successful exploitation of CVE-2026-40379 can lead to unauthorized access to sensitive resources and data within an organization's Azure Entra ID environment. An attacker could potentially impersonate legitimate users or services, leading to data breaches, financial loss, or disruption of business operations. The scope of the impact depends on the permissions and access levels of the compromised user or service.

## Recommendation

*   Monitor Azure Entra ID logs for suspicious authentication attempts and token issuance patterns that may indicate exploitation of CVE-2026-40379.
*   Deploy the provided Sigma rule to detect suspicious token activity based on CVE-2026-40379.
*   Review and harden ESTS configurations within Azure Entra ID to minimize the attack surface and potential for information exposure.
