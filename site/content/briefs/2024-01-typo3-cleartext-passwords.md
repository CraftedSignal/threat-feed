---
title: TYPO3 CMS 14.2.0 Stores Passwords in Cleartext
slug: 2024-01-typo3-cleartext-passwords
description: TYPO3 CMS version 14.2.0 stores passwords in cleartext in the `uc` and `user_settings` fields of the `be_users` database table when users change their credentials in the backend user settings module.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - typo3
  - cleartext-password
  - credential-access
  - cve-2026-6553
vendors:
  - TYPO3
products:
  - CMS Backend
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://github.com/advisories/GHSA-xvv6-p4wf-mvx7
rules:
  - title: Detect Access to be_users Table After Password Change
    description: Detects potential unauthorized access to the be_users table shortly after a password change, which may indicate attempts to retrieve cleartext passwords in vulnerable TYPO3 instances.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
      - T1003.008
    data_sources:
      - database
      - mysql
rules_count: 1
---

TYPO3 CMS version 14.2.0 contains a vulnerability where user passwords are stored in cleartext within the `uc` and `user_settings` fields of the `be_users` database table. This issue arises due to the `SetupModuleController` incorrectly conflating entity data with user-interface settings during persistence. The vulnerability is triggered when backend users modify their credentials through the backend user settings module while using the affected TYPO3 version. This flaw, reported by Martin Clewing and addressed by the TYPO3 core team, poses a significant risk as it exposes user credentials to unauthorized access and potential compromise. Defenders should prioritize upgrading to TYPO3 version 14.3.0 LTS and executing the User Settings Scrubbing wizard.

## Attack Chain

1. An attacker gains unauthorized access to the TYPO3 backend, potentially through brute-force attacks or stolen credentials.
2. The attacker navigates to the backend user settings module.
3. A legitimate user or the attacker changes their password within the module while the TYPO3 instance is running version 14.2.0.
4. The `SetupModuleController` processes the password change request.
5. Instead of properly hashing the password, the `SetupModuleController` stores it in cleartext in the `uc` and `user_settings` fields of the `be_users` database table.
6. An attacker with database access can now retrieve the cleartext passwords from these fields.
7. The attacker uses the compromised credentials to impersonate the user and gain access to sensitive data or perform unauthorized actions.

## Impact

Successful exploitation of this vulnerability allows attackers with database access to retrieve cleartext passwords, potentially leading to complete compromise of backend user accounts. While the vulnerability is limited to TYPO3 CMS version 14.2.0, the impact on affected instances is significant, as administrative accounts could be hijacked, allowing attackers to modify website content, install malicious extensions, or exfiltrate sensitive data. This could result in data breaches, financial loss, and reputational damage.

## Recommendation

*   Upgrade to TYPO3 version 14.3.0 LTS to address the underlying vulnerability (reference: Solution section).
*   Execute the User Settings Scrubbing wizard in the TYPO3 Install Tool to sanitize existing cleartext passwords in the `uc` and `user_settings` fields (reference: Solution section).
*   Require affected backend user accounts to reset their passwords immediately (reference: Solution section).
*   Monitor database access logs for suspicious activity, especially access to the `be_users` table (reference: Attack Chain).
*   Deploy the Sigma rule provided below to detect potential unauthorized access attempts following password changes.
