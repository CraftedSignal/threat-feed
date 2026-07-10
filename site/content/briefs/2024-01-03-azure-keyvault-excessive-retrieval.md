---
title: Azure Key Vault Excessive Secret or Key Retrieval
slug: 2024-01-03-azure-keyvault-excessive-retrieval
description: Detects excessive secret or key retrieval operations from Azure Key Vault, indicating potential unauthorized access attempts or credential harvesting.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - keyvault
  - credential-access
  - threat-detection
vendors:
  - Microsoft
products:
  - Azure Key Vault
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/credential_access_key_vault_excessive_retrieval.toml
  - https://www.inversecos.com/2022/05/detection-and-compromise-azure-key.html
rules:
  - title: Azure Key Vault Excessive Secret Retrieval via UPN
    description: Detects excessive secret or key retrievals from Azure Key Vault by a single user principal name within a short time frame.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555.006
    data_sources:
      - cloudtrail
      - azure
      - keyvault
  - title: Azure Key Vault Enumeration
    description: Detects Key Vault enumeration attempts by monitoring for a high number of list operations.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - cloudtrail
      - azure
      - keyvault
rules_count: 2
---

This rule identifies excessive secret or key retrieval operations from Azure Key Vault, a cloud service safeguarding encryption keys and secrets. The rule detects instances where a user principal retrieves secrets or keys from Azure Key Vault multiple times within a short timeframe, potentially indicating abuse or unauthorized access attempts. The rule focuses on high-frequency retrieval operations that deviate from normal user behavior, suggesting credential harvesting or misuse of sensitive information. An adversary might abuse a FOCI (Foreign Ownership, Control, or Influence) compliant application to evade security controls or conditional access policies, and use that to access the secrets. Published on 2026-04-10, this rule is designed to alert on potentially malicious behavior within Azure environments using data ingested into Elastic.

## Attack Chain

1.  An attacker gains initial access to an Azure environment, potentially through compromised credentials or exploiting a vulnerability.
2.  The attacker identifies an Azure Key Vault containing sensitive secrets or keys.
3.  The attacker attempts to retrieve secrets or keys from the Key Vault using valid or stolen credentials.
4.  The attacker iterates through various Key Vault resources, attempting to access a wide range of secrets.
5.  The attacker's activity generates multiple "KeyGet", "SecretGet", or "CertificateGet" events within a short time frame, triggering the detection rule.
6.  The attacker exfiltrates the retrieved secrets or keys for use in further malicious activities.
7.  The attacker uses the obtained credentials to access sensitive data or systems.
8.  The attacker achieves their objective, such as data theft or unauthorized system access.

## Impact

Excessive key and secret retrievals can indicate that an attacker is attempting to compromise sensitive data stored within Azure Key Vault. Successful credential access can lead to unauthorized access to other Azure resources, data breaches, and service disruptions. The rule is triggered when a principal retrieves more than 10 key vault items and at least 2 distinct actions in a 1 minute window. This can lead to significant financial and reputational damage depending on the sensitivity of the compromised data.

## Recommendation

*   Enable Azure Key Vault diagnostic logs, specifically the AuditEvent log, to capture read and write operations (as mentioned in the rule's setup section).
*   Deploy the provided Sigma rule "Azure Key Vault Excessive Secret Retrieval via UPN" to your SIEM to detect suspicious retrieval activity based on User Principal Name, tuning the threshold (Esql.event_count >= 10) for your environment.
*   Investigate alerts triggered by the Sigma rule by reviewing the `azure.platformlogs.identity.claim.upn`, `azure.platformlogs.identity.claim.appid`, and `source.ip` fields in the logs to identify the source and user involved.
*   Implement stricter access controls and policies for Key Vaults to limit excessive retrievals, ensuring only authorized users and applications can access sensitive keys and secrets.
*   Triage users flagged by this rule with Entra ID sign-in logs to gather more context about their authentication behavior, as described in the rule's "Triage and Analysis" section.
