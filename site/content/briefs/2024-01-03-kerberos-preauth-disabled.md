---
title: Kerberos Pre-Authentication Disabled for User Account
slug: 2024-01-03-kerberos-preauth-disabled
description: Detection of the Kerberos pre-authentication flag being disabled in a user account via Windows Security Event 4738, enabling AS-REP Roasting attacks for offline password brute-forcing.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kerberos
  - as-rep roasting
  - credential-access
  - active directory
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
references:
  - https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
  - https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
  - https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/
rules:
  - title: Detect Kerberos Pre-Authentication Disabled via Event 4738
    description: Detects disabling Kerberos pre-authentication by monitoring Windows Security Event 4738 for changes to UserAccountControl.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - process_creation
      - windows
  - title: Kerberos Pre-Authentication Flag Disabled in UserAccountControl - Sysmon
    description: Detects when the Kerberos Pre-Authentication flag is disabled in a user account, using Sysmon to monitor process creation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief addresses the threat of adversaries disabling the Kerberos pre-authentication requirement for user accounts within an Active Directory environment. The detection focuses on Windows Security Event 4738, which logs modifications to user account attributes, specifically the UserAccountControl flag. By disabling pre-authentication, attackers can exploit the AS-REP Roasting technique to obtain Kerberos tickets without requiring prior authentication. This allows for offline brute-force attacks against user passwords. This tactic is often used by attackers who have already gained initial access and are attempting to escalate privileges or establish persistence. Successful exploitation can lead to complete domain compromise.

## Attack Chain

1.  The attacker gains initial access to a system within the target network (e.g., via compromised credentials or phishing).
2.  The attacker uses an account with sufficient privileges (e.g., Domain Admin or Account Operators) to modify the UserAccountControl attribute of a target user account.
3.  The attacker disables the "Do not require Kerberos preauthentication" flag for the target user account. This is reflected in Windows Security Event 4738 with UserAccountControl containing the value "%%2096".
4.  The attacker requests Kerberos service tickets (TGS) for services accessible by the target user account.
5.  Since pre-authentication is disabled, the Domain Controller issues the TGS without requiring the user to prove their identity. This is the AS-REP response.
6.  The attacker captures the AS-REP response, which contains a hash derived from the user's password.
7.  The attacker performs offline brute-force attacks against the captured hash to recover the user's password using tools like Hashcat or John the Ripper.
8.  The attacker uses the cracked password to authenticate as the target user and gain access to resources and data.

## Impact

Successful AS-REP Roasting attacks can lead to the compromise of user accounts, granting attackers unauthorized access to sensitive data and systems. Depending on the privileges of the compromised account, attackers may be able to escalate their privileges further, move laterally within the network, and potentially achieve complete domain dominance. The number of affected accounts depends on the attacker's targeting and the effectiveness of their password cracking efforts. This attack can result in data breaches, financial loss, and reputational damage.

## Recommendation

*   Enable the "User Account Management" advanced security audit policy to ensure Windows Security Event 4738 is generated (reference: data_source).
*   Deploy the provided Sigma rule to your SIEM to detect instances of UserAccountControl modifications that disable Kerberos pre-authentication (reference: rules).
*   Investigate all detected instances of Event ID 4738 where the UserAccountControl attribute includes "%%2096" (reference: search query).
*   Review user accounts to ensure that the "Do not require Kerberos preauthentication" flag is only enabled when absolutely necessary and with proper justification (reference: description).
*   Monitor network traffic for unusual Kerberos ticket requests, potentially indicating AS-REP roasting attempts (generic Kerberos monitoring).
