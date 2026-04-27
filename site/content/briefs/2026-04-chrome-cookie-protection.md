---
title: Google Chrome Device Bound Session Credentials (DBSC) Mitigates Cookie Theft
slug: 2026-04-chrome-cookie-protection
description: Google's rollout of Device Bound Session Credentials (DBSC) in Chrome 146 for Windows, with a future release planned for macOS, cryptographically binds authentication sessions to the user's device, rendering stolen session cookies unusable and mitigating credential access.
date: "2026-04-10T07:50:52Z"
severities:
  - medium
tags:
  - cookie-theft
  - credential-access
  - chrome
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://www.securityweek.com/google-rolls-out-cookie-theft-protections-in-chrome/
rules:
  - title: Detect Process Accessing Chrome Cookie Files
    description: Detects processes attempting to access Chrome cookie files, potentially indicating cookie theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - file_event
      - windows
  - title: Detect Process Accessing Chrome Cookie Files (MacOS)
    description: Detects processes attempting to access Chrome cookie files on macOS, potentially indicating cookie theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - file_event
      - macos
rules_count: 2
---

Google has introduced Device Bound Session Credentials (DBSC) in Chrome 146 for Windows to combat session cookie theft, with a macOS version planned for a future release. This feature, initially announced in April 2024, aims to protect user accounts from compromise by rendering stolen authentication cookies useless. Session cookies are often stolen using information-stealing malware and traded on cybercrime platforms, allowing attackers to access accounts without passwords. DBSC mitigates this…
