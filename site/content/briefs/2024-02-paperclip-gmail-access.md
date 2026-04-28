---
title: Paperclip codex_local Unauthorized Gmail Access
slug: 2024-02-paperclip-gmail-access
description: A Paperclip-managed `codex_local` runtime can access and utilize Gmail connectors connected in the ChatGPT/OpenAI apps UI without explicit Paperclip configuration, allowing unauthorized mailbox access and email sending capabilities due to a trust-boundary failure and dangerous default runtime settings.
date: "2026-04-16T22:47:40Z"
type: coverage
types:
  - coverage
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

A critical vulnerability exists within the Paperclip AI ecosystem, specifically affecting the `codex_local` runtime environment. The core issue stems from a trust-boundary failure, where a Paperclip-managed `codex_local` runtime gains unauthorized access to Gmail connectors that were previously configured within the broader ChatGPT/OpenAI apps UI. This unintended inheritance of connector permissions allows the `codex_local` environment to perform actions, such as reading emails and sending messages, without explicit authorization within Paperclip itself. This is further complicated by the `codex_local` runtime's default setting of `dangerouslyBypassApprovalsAndSandbox` to `true`, which effectively disables security controls and amplifies the risk associated with the connector access.  This issue was identified in Paperclip versions up to and including 2026.403.0. Successful exploitation bypasses intended permission boundaries and poses a significant risk to user data and privacy.

## Attack Chain

1. User connects their Gmail account within the ChatGPT/OpenAI apps UI for use with other OpenAI services.
2. A self-hosted Paperclip instance is deployed, utilizing the `codex_local` runtime.
3. A `codex_local` agent is created and initiated, operating under default settings, which include `dangerouslyBypassApprovalsAndSandbox = true`.
4. The `codex_local` runtime accesses cached OpenAI curated connector state for Gmail found within the `codex-home/plugins/cache/openai-curated/gmail/.../.app.json` path.
5. The agent executes a task designed to inspect mailbox contents, leveraging the inherited Gmail connector.
6.  The agent makes successful `mcp__codex_apps__gmail_get_profile`, `mcp__codex_apps__gmail_search_emails`, and `mcp__codex_apps__gmail_send_email` calls.
7.  An email is sent from the user's Gmail account to an unintended recipient without explicit user authorization or Paperclip configuration.
8.  Subsequent "retraction" emails are sent, further demonstrating the persistent and unauthorized write access to the Gmail account.

## Impact

The unauthorized access to Gmail connectors through Paperclip's `codex_local` runtime has severe consequences. It enables attackers to perform actions, such as disclosing mailbox identity, accessing email threads, and sending emails to external third parties without explicit user consent. In a real-world scenario, this resulted in the sending of an email from a user's personal Gmail account to an unintended external recipient, and follow-up retraction messages, highlighting the potential for significant reputational damage and data breaches. The inherent trust boundary failure and unsafe default settings significantly amplify the risk, making it critical to address these vulnerabilities.

## Recommendation

*   Disable or restrict the default inheritance of OpenAI app connectors within Paperclip-managed `codex_local` runs to prevent unintended access to services like Gmail.
*   Implement a default-deny policy for send/write connectors, requiring explicit Paperclip-side opt-in before any outward actions are permitted.
*   Modify the `codex_local` runtime defaults to ensure safer configurations, including setting `dangerouslyBypassApprovalsAndSandbox = false`.
*   Implement the Sigma rules provided to detect unauthorized Gmail API calls originating from the Paperclip environment.
