---
title: RagaSerpent 'Tax Audit' Campaign Targeting Multiple Countries
slug: 2026-03-ragaserpent-tax-audit
description: The RagaSerpent cluster, also known as SideWinder-Adjacent, is conducting targeted attacks across multiple countries between 2025 and 2026, associated with a 'Tax Audit' themed campaign.
date: "2026-03-21T12:00:00Z"
severities:
  - medium
actors:
  - RagaSerpent
tags:
  - RagaSerpent
  - SideWinder
  - Tax Audit
  - Spearphishing
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rynn0g/ragaserpent_aka_sidewinderadjacent_tax_audit/
rules:
  - title: Detect Suspicious Process Execution from Office Applications
    description: Detects suspicious process executions originating from Microsoft Office applications, which may indicate exploitation attempts via malicious documents.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Outbound Connection by Uncommon Process
    description: Detects suspicious network connections initiated by processes that are not commonly associated with network activity. This can indicate compromised systems communicating with C2 servers.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The RagaSerpent cluster, sometimes referred to as SideWinder-Adjacent, is an active threat actor targeting multiple countries between 2025 and 2026. Their activities are characterized by a campaign centered around a "Tax Audit" theme. This suggests potential targeting of individuals or organizations involved in financial activities or government entities responsible for tax administration. While specific technical details are limited in this brief, the multi-country scope and the social…
