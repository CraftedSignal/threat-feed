---
title: VoidStealer Steals Secrets by Debugging Chrome
slug: 2024-01-23-voidstealer-chrome-debugging
description: VoidStealer leverages Chrome debugging capabilities to extract sensitive information, such as credentials and session cookies, directly from the browser's memory.
date: "2026-03-20T05:48:21Z"
severities:
  - high
actors:
  - VoidStealer
tags:
  - credential-theft
  - chrome
  - debugging
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ryo42s/voidstealer_debugging_chrome_to_steal_its_secrets/
  - https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass
rules:
  - title: Suspicious Chrome Debugging Attachment
    description: Detects processes attaching to Chrome for debugging purposes, which may indicate VoidStealer activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.005
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Accessing Chrome Memory
    description: Detects processes accessing memory regions of Chrome, which may indicate VoidStealer memory scraping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

VoidStealer is a threat actor utilizing advanced techniques to extract sensitive information from Google Chrome. This is achieved by abusing Chrome's built-in debugging features. The threat actor's primary goal is to steal credentials, session cookies, and potentially other sensitive data stored within the browser's memory. This allows for account takeover and lateral movement within compromised environments. The technique bypasses traditional security measures, as it operates within a…
