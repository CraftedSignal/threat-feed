---
title: Paperclip codex_local Unauthorized Gmail Access
slug: 2024-02-paperclip-gmail-access
description: A Paperclip-managed `codex_local` runtime can access and utilize Gmail connectors connected in the ChatGPT/OpenAI apps UI without explicit Paperclip configuration, allowing unauthorized mailbox access and email sending capabilities due to a trust-boundary failure and dangerous default runtime settings.
date: "2026-04-16T22:47:40Z"
severities:
  - high
tags:
  - paperclipai
  - gmail
  - openai
  - authorization bypass
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://github.com/advisories/GHSA-gqqj-85qm-8qhf
rules:
  - title: Detect Paperclip Gmail API Calls
    description: Detects process execution that makes Gmail API calls within a Paperclip environment, indicating potential unauthorized access.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
  - title: Detect Codex Home Access to Gmail Connector Cache
    description: Detects processes accessing the Gmail connector cache directory within the Paperclip's codex-home, indicating potential unauthorized access to Gmail configurations.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists within the Paperclip AI ecosystem, specifically affecting the `codex_local` runtime environment. The core issue stems from a trust-boundary failure, where a Paperclip-managed `codex_local` runtime gains unauthorized access to Gmail connectors that were previously configured within the broader ChatGPT/OpenAI apps UI. This unintended inheritance of connector permissions allows the `codex_local` environment to perform actions, such as reading emails and sending…
