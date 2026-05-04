---
title: Account Configured with Never-Expiring Password
slug: 2024-01-never-expiring-password
description: Detects the creation and modification of an account with the 'Don't Expire Password' option enabled, which attackers can abuse to persist in the domain and maintain long-term access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - account-manipulation
vendors:
  - Microsoft
products:
  - Active Directory
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#dont_expire
  - http://web.archive.org/web/20230329171952/https://blog.menasec.net/2019/02/threat-hunting-26-persistent-password.html
rules:
  - title: Account Configured with Never-Expiring Password (Event ID 4738)
    description: Detects modification of an account with the 'Don't Expire Password' option enabled via Event ID 4738.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
  - title: Account Configured with Never-Expiring Password (Event ID 5136)
    description: Detects modification of an account with the 'Don't Expire Password' option enabled via Event ID 5136.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse accounts configured with never-expiring passwords to maintain long-term access within a compromised environment. This persistence technique leverages the Active Directory setting that prevents password expiration. While sometimes legitimately used for service accounts, this configuration weakens security posture and exposes environments to credential access attacks. The rule detects Event ID 4738 (User Account Modified) with the NewUACList containing "USER_DONT_EXPIRE_PASSWORD", and Event ID 5136 (Directory Service Changes) where the userAccountControl attribute is modified with specific values (66048 or 66080). These values indicate that the 'Password never expires' flag has been set on the account. Defender should monitor for such events and take immediate remediation actions.

## Attack Chain

1. An attacker gains initial access to a domain-joined system, potentially through phishing or exploiting a public-facing application.
2. The attacker performs reconnaissance to identify accounts suitable for long-term persistence, focusing on privileged accounts or those with minimal monitoring.
3. The attacker uses compromised credentials or exploits a privilege escalation vulnerability to gain administrative access to Active Directory.
4. The attacker modifies the target account's attributes using tools like `net user` or PowerShell cmdlets from the Active Directory module.
5. Specifically, the attacker sets the `userAccountControl` attribute to disable password expiration for the chosen account.
6. The attacker validates the configuration change to ensure the password expiration is disabled, allowing for persistent access.
7. With a never-expiring password, the attacker can maintain access to the compromised account indefinitely, even after password resets or other security measures are implemented on other accounts.

## Impact

Successful exploitation allows attackers to maintain a persistent presence within the compromised domain. This can lead to data theft, further lateral movement, or disruption of services.  The impact is increased if the affected account has elevated privileges, granting the attacker broader access to sensitive resources. While the number of affected organizations is unknown, the technique is applicable to any organization using Active Directory.

## Recommendation

*   Enable and monitor Windows audit policies for User Account Management and Directory Service Changes to generate relevant events.
*   Deploy the Sigma rule "Account Configured with Never-Expiring Password" to your SIEM and tune for your environment.
*   Regularly review and audit accounts with the "Don't Expire Password" option enabled, and enforce the use of Group Managed Service Accounts (gMSA) where appropriate.
*   Use the provided PowerShell command (`get-aduser -filter { passwordNeverExpires -eq $true  -and enabled -eq $true } | ft`) to identify accounts with passwordNeverExpires enabled across the domain.
