---
title: Azure AD Bitlocker Key Retrieval
slug: 2024-01-bitlocker-key-retrieval
description: An adversary with sufficient privileges in Azure Active Directory may attempt to retrieve BitLocker keys to decrypt drives for lateral movement or data exfiltration.
date: "2024-01-03T18:29:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - bitlocker
  - key-retrieval
  - persistence
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-devices#bitlocker-key-retrieval
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_bitlocker_key_retrieval.yml
rules:
  - title: Azure AD Bitlocker Key Retrieval
    description: Detects Bitlocker key retrieval operations in Azure AD audit logs, which can indicate potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD Bitlocker Key Retrieval by Uncommon User
    description: Detects Bitlocker key retrieval operations in Azure AD audit logs, focusing on potentially anomalous users performing the action.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078.004
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

Attackers with access to Azure Active Directory, either through compromised credentials or an insider threat, can retrieve BitLocker recovery keys stored within the Azure environment. This allows them to decrypt volumes protected with BitLocker encryption. While retrieving BitLocker keys is a legitimate administrative function, anomalous or unauthorized access can indicate malicious activity. Attackers may leverage this to gain unauthorized access to encrypted data, escalate privileges, or move laterally within the compromised environment. Defenders need to monitor BitLocker key retrieval events for unusual patterns or unauthorized access attempts to detect and prevent potential data breaches or other malicious activities.

## Attack Chain

1. Initial Access: An attacker gains unauthorized access to an Azure Active Directory account with sufficient privileges, possibly via credential phishing or password spraying (T1078.004).
2. Privilege Escalation (if needed): The attacker escalates privileges within Azure AD if the initially compromised account lacks the necessary permissions to read BitLocker keys.
3. Discovery: The attacker uses Azure AD tools or PowerShell cmdlets to identify devices with BitLocker encryption enabled.
4. Key Retrieval: The attacker uses the Azure portal or PowerShell to retrieve the BitLocker recovery key for a specific device. This generates an audit log event.
5. Offline Access: The attacker uses the retrieved BitLocker recovery key to unlock the encrypted drive on a compromised system or a copied disk image.
6. Data Exfiltration or Lateral Movement: With the drive unlocked, the attacker can access sensitive data, install malware, or use the system for lateral movement within the network.

## Impact

Successful BitLocker key retrieval can lead to unauthorized access to sensitive data stored on encrypted drives. This could result in data breaches, financial loss, reputational damage, and legal liabilities. The impact depends on the sensitivity and volume of data stored on the encrypted volumes, as well as the attacker's subsequent actions.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect BitLocker key retrieval events in Azure Audit Logs.
*   Review Azure AD access logs for suspicious activity related to user accounts that have permissions to read BitLocker keys (reference: Sigma rule).
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges in Azure AD, to prevent unauthorized access (T1078.004).
*   Implement Conditional Access policies to restrict access to sensitive Azure resources, including BitLocker recovery keys, based on factors such as location, device, and user risk.
*   Regularly review and audit Azure AD roles and permissions to ensure that users only have the necessary privileges to perform their job functions.
