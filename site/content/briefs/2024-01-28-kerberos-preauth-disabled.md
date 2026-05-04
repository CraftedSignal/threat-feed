---
title: Kerberos Pre-authentication Disabled for User Account
slug: 2024-01-28-kerberos-preauth-disabled
description: Detection of Kerberos pre-authentication being disabled for a user account, potentially leading to AS-REP roasting and offline password cracking by attackers with GenericWrite or GenericAll rights over the account.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kerberos
  - credential-access
  - as-rep-roasting
  - active-directory
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://harmj0y.medium.com/roasting-as-reps-e6179a65216b
  - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738
  - https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0026_windows_audit_user_account_management.md
rules:
  - title: Kerberos Pre-authentication Disabled via Event ID 4738
    description: Detects when Kerberos pre-authentication is disabled for a user account by monitoring Windows Event ID 4738.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1558.004
    data_sources:
      - windows
      - windows
  - title: PowerShell Modification of Kerberos Pre-Authentication
    description: Detects the use of PowerShell to modify user account settings to disable Kerberos pre-authentication.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.001
      - T1098
      - T1558.004
    data_sources:
      - process_creation
      - windows
  - title: Cmd.exe Modification of Kerberos Pre-Authentication
    description: Detects the use of cmd.exe to modify user account settings to disable Kerberos pre-authentication using dsmod command.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1078.002
      - T1098
      - T1558.004
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies instances where the Kerberos pre-authentication requirement is disabled for a user account within an Active Directory environment. Attackers with `GenericWrite` or `GenericAll` permissions over a target account can modify the `UserAccountControl` attribute to disable pre-authentication. This configuration weakens the account's security posture, making it vulnerable to AS-REP roasting attacks, where attackers can request Kerberos tickets and crack the password offline. The activity is logged as Event ID 4738 in the Windows Security Event Logs, specifically when the `NewUACList` includes the `USER_DONT_REQUIRE_PREAUTH` flag. This poses a significant risk, especially if applied to privileged accounts, as it allows adversaries to potentially compromise credentials and escalate privileges within the domain. The detection is based on research and recommendations from Microsoft regarding Kerberos security best practices.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to an account with sufficient privileges (e.g., Domain Admin, or an account with delegated permissions) to modify user account attributes in Active Directory.
2.  **Privilege Escalation:** The attacker leverages their initial access to target a specific user account for which they intend to disable Kerberos pre-authentication.
3.  **Account Modification:** The attacker modifies the `UserAccountControl` attribute of the target user account, specifically disabling the "Do not require pre-authentication" setting (setting the `USER_DONT_REQUIRE_PREAUTH` flag). This is often done using tools like `Active Directory Users and Computers` or PowerShell cmdlets.
4.  **Event Logging:** The modification triggers a Windows Security Event Log event (Event ID 4738) on the Domain Controller, indicating that the user account attribute has been changed. The `NewUACList` field in the event data contains `USER_DONT_REQUIRE_PREAUTH`.
5.  **AS-REQ Request:** The attacker crafts an AS-REQ (Authentication Service Request) to the Kerberos Key Distribution Center (KDC) for the targeted user account. Since pre-authentication is disabled, the KDC processes the request without requiring pre-authentication.
6.  **AS-REP Response:** The KDC issues an AS-REP (Authentication Service Response) to the attacker, containing an encrypted Ticket Granting Ticket (TGT) for the targeted user account.
7.  **Offline Cracking:** The attacker extracts the encrypted TGT from the AS-REP response and attempts to crack it offline using password cracking tools and techniques, such as hashcat or John the Ripper.
8.  **Credential Access:** Upon successfully cracking the TGT, the attacker obtains the plaintext password for the targeted user account. This password can then be used for lateral movement, privilege escalation, and further malicious activities within the domain.

## Impact

Compromising user accounts through AS-REP roasting can have significant consequences. Attackers can gain unauthorized access to sensitive resources, escalate privileges, and move laterally within the network. Successful AS-REP roasting leads to credential compromise, which could result in data breaches, system compromise, and disruption of services. Organizations failing to monitor and prevent Kerberos pre-authentication disabling are at an increased risk of credential theft and subsequent exploitation, potentially affecting all systems within the compromised domain.

## Recommendation

*   Enable "Audit User Account Management" and ensure Windows Security Event Logs (specifically Event ID 4738) are being collected and forwarded to your SIEM for analysis as described in the setup instructions linked in the rule source.
*   Deploy the provided Sigma rule to detect Event ID 4738 events where the `NewUACList` contains `USER_DONT_REQUIRE_PREAUTH` within your environment to identify potential AS-REP roasting vulnerabilities.
*   Investigate any instances of disabled pre-authentication, especially on privileged accounts, following the triage steps outlined in the rule documentation.
*   Enforce the principle of least privilege by reviewing and restricting the privileges assigned to users and groups to prevent unauthorized modification of Active Directory user account attributes.
*   Monitor for suspicious Kerberos authentication patterns and investigate any anomalies that might indicate AS-REP roasting attempts.
