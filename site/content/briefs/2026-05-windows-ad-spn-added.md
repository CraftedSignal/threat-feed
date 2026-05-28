---
title: Windows AD ServicePrincipalName Added To Domain Account
slug: 2026-05-windows-ad-spn-added
description: This Splunk analytic detects the addition of a Service Principal Name (SPN) to a domain account by monitoring Windows Event Code 5136 and changes to the servicePrincipalName attribute, potentially indicating Kerberoasting attempts leading to unauthorized access.
date: "2026-05-28T18:00:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kerberoasting
  - active_directory
  - spn
  - persistence
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://adsecurity.org/?p=3466
  - https://www.thehacker.recipes/ad/movement/dacl/targeted-kerberoasting
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
  - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
rules:
  - title: Detect SPN Added To User Account
    description: Detects the addition of a Service Principal Name (SPN) to a user account, which can indicate a Kerberoasting attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Event 5136 - SPN Added
    description: Detects Windows Event ID 5136 indicating a servicePrincipalName was added to an account.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This analytic identifies when a Service Principal Name (SPN) is added to a domain account in Windows Active Directory. The detection uses Windows Event Code 5136, specifically monitoring changes to the `servicePrincipalName` attribute of user objects. The addition of an SPN to an account can be a legitimate administrative action; however, it is also a common precursor to Kerberoasting attacks. Attackers may add SPNs to accounts they control, or to existing service accounts, to facilitate the extraction of Kerberos tickets for offline password cracking, which can lead to credential compromise and lateral movement within the network. The technique is significant because successful Kerberoasting can provide attackers with cleartext passwords, enabling them to compromise critical services and gain persistent access to the domain.

## Attack Chain

1.  Attacker gains initial access to a domain-joined machine through phishing or exploiting a public-facing application.
2.  The attacker performs reconnaissance to identify existing service accounts or user accounts suitable for Kerberoasting.
3.  The attacker uses tools like `setspn.exe` or PowerShell to add a new `servicePrincipalName` attribute to a target domain account. This requires elevated privileges within the domain.
4.  Windows Event 5136 is generated, logging the modification of the `servicePrincipalName` attribute on the target account.
5.  The attacker requests a Kerberos ticket for the newly created SPN using tools like `Rubeus.exe` or `GetUserSPNs.ps1`.
6.  The Kerberos ticket is captured in memory or saved to disk.
7.  The attacker performs offline password cracking on the captured Kerberos ticket using tools like Hashcat or John the Ripper.
8.  If the password is successfully cracked, the attacker uses the compromised credentials to move laterally within the domain, access sensitive data, or establish persistence.

## Impact

A successful Kerberoasting attack can compromise service accounts, providing attackers with elevated privileges and access to sensitive resources. This can lead to data breaches, system compromise, and significant financial losses. The impact is especially high if the compromised account has access to critical systems or sensitive data. Kerberoasting can also lead to lateral movement and persistent access within the domain.

## Recommendation

*   Enable the Advanced Security Audit policy setting `Audit Directory Services Changes` within `DS Access` and create a SACL for AD objects to ingest attribute modifications, as mentioned in the "how_to_implement" section, to ensure proper logging of SPN modifications.
*   Deploy the Sigma rule `Detect SPN Added To User Account` to your SIEM and tune for your environment based on known legitimate SPN modifications.
*   Investigate any instances of EventCode 5136 where the `servicePrincipalName` attribute is modified, especially when the ObjectClass is "user", based on the event code mentioned in the detection's search query.
*   Review the references provided, especially [https://adsecurity.org/?p=3466](https://adsecurity.org/?p=3466), to better understand Kerberoasting attack techniques and indicators.
