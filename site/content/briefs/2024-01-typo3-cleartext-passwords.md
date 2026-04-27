---
title: TYPO3 CMS 14.2.0 Stores Passwords in Cleartext
slug: 2024-01-typo3-cleartext-passwords
description: TYPO3 CMS version 14.2.0 stores passwords in cleartext in the `uc` and `user_settings` fields of the `be_users` database table when users change their credentials in the backend user settings module.
date: "2024-01-30T12:00:00Z"
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

TYPO3 CMS version 14.2.0 contains a vulnerability where user passwords are stored in cleartext within the `uc` and `user_settings` fields of the `be_users` database table. This issue arises due to the `SetupModuleController` incorrectly conflating entity data with user-interface settings during persistence. The vulnerability is triggered when backend users modify their credentials through the backend user settings module while using the affected TYPO3 version. This flaw, reported by Martin…
