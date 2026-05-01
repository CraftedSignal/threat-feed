---
title: PowerShell Kerberos Ticket Request via KerberosRequestorSecurityToken
slug: 2024-01-09-kerberos-ticket-request
description: This rule detects PowerShell scripts that request Kerberos service tickets using KerberosRequestorSecurityToken, potentially indicating Kerberoasting attacks for offline password cracking of service accounts.
date: "2024-01-09T18:45:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kerberoasting
  - credential_access
  - windows
vendors:
  - Elastic
products:
  - Elastic Security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
references:
  - https://www.cobalt.io/blog/kerberoast-attack-techniques
  - https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1
rules:
  - title: PowerShell Kerberos Ticket Request
    description: Detects PowerShell scripts that use KerberosRequestorSecurityToken to request Kerberos service tickets, which may indicate Kerberoasting attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558.003
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Kerberos Ticket Request via Script Block Logging
    description: Detects PowerShell scripts that use KerberosRequestorSecurityToken to request Kerberos service tickets, which may indicate Kerberoasting attempts, using Script Block Logging.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies PowerShell scripts leveraging the `KerberosRequestorSecurityToken` class to request Kerberos service tickets. Attackers often use this technique to perform Kerberoasting, where they obtain service tickets for various service principal names (SPNs) and crack the associated service account passwords offline. This activity can be indicative of an attacker attempting to gain unauthorized access to sensitive resources within the network. The rule is designed to trigger on potentially malicious uses of `KerberosRequestorSecurityToken` while attempting to filter out legitimate uses, such as those within Sentinel breakpoints or authorized Kerberos diagnostic scripts. Defenders should investigate any instances of this activity to determine whether it represents a genuine threat.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a Windows system, potentially through phishing, compromised credentials, or exploiting a vulnerability.
2.  **Execution:** The attacker executes a PowerShell script, either interactively or via a scheduled task or other means of remote execution.
3.  **Obfuscation (Optional):** The PowerShell script may be obfuscated to evade detection, using techniques such as Base64 encoding or string manipulation.
4.  **Ticket Request:** The script uses the `KerberosRequestorSecurityToken` class to request Kerberos service tickets for one or more SPNs.
5.  **Data Collection:** The script collects the requested service tickets and potentially saves them to a file or transmits them over the network.
6.  **Credential Access:** The attacker extracts the Kerberos hashes from the collected tickets.
7.  **Offline Cracking:** The attacker uses tools like John the Ripper or Hashcat to crack the service account passwords offline.
8.  **Privilege Escalation/Lateral Movement:** Upon successfully cracking the passwords, the attacker uses the compromised credentials to escalate privileges or move laterally within the network.

## Impact

Successful Kerberoasting attacks can lead to the compromise of service accounts, potentially granting attackers unauthorized access to critical systems and sensitive data. The impact can range from data breaches and financial losses to complete system compromise and disruption of business operations. The rule's medium severity reflects the potential for significant impact if the attack succeeds.

## Recommendation

*   Enable PowerShell Script Block Logging to capture the PowerShell script content necessary for detection, and ensure the logs are being ingested into your SIEM. Reference: [Setup instructions](https://ela.st/powershell-logging-setup).
*   Deploy the Sigma rule "PowerShell Kerberos Ticket Request" to your SIEM to detect suspicious use of `KerberosRequestorSecurityToken` in PowerShell scripts.
*   Investigate any alerts triggered by the Sigma rule, focusing on reconstructing the full script content, identifying the targeted SPNs, and analyzing the process execution context to determine if the activity is malicious.
*   Review Windows Security event logs on domain controllers for event ID 4769, filtering for the `TargetUserName` associated with the alerting user to identify related Kerberos ticket requests.
