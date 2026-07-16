---
title: ClickFix Campaign Activity
slug: 2026-07-clickfix-campaign
description: Tracking brief for the ClickFix campaign; individual sightings are folded in as reported.
date: "2026-07-06T12:44:38Z"
lastmod: "2026-07-16T08:52:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - campaign
  - clickfix
vendors:
  - GitHub
  - Google
  - Noma Labs
  - Anthropic
  - JustWatch GmbH
  - Microsoft
  - Telegram
  - Brazilian Government
  - Banco do Brasil
products:
  - open source packages
  - GitHub repositories
  - NPM packages
  - Packagist packages
  - Go modules
  - Chrome extensions
  - GitHub Agentic Workflows
  - GitHub AI agent
  - GitHub Actions
  - GitHub Copilot
  - Claude
  - Windows Defender
  - Windows AMSI
  - Telegram
  - .gov.br municipal portals
  - .gov.br police portals
affected_os:
  - Windows
references:
  - https://www.securityweek.com/north-korean-hackers-target-open-source-developers-in-supply-chain-attacks/
  - https://hackread.com/gitlost-github-ai-agent-leaking-repository-data/
  - https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/
  - https://www.reddit.com/r/blueteamsec/comments/1uxuh7t/telepuz_a_modular_maas_malware_spreading_via/
  - https://any.run/cybersecurity-blog/phantomenigma-research/
iocs:
  - type: github_account_name
    value: Xpos587
  - type: packagist_namespace
    value: sevenspan
  - type: malware_name
    value: DEV#POPPER
  - type: malware_name
    value: OmniStealer
  - type: domain
    value: justwatch.com
  - type: ip
    value: 136.243.203.109
  - type: domain
    value: pool.supportxmr.com
  - type: domain
    value: ip-api.com
  - type: domain
    value: .gov.br
ioc_counts:
  domain: 4
  github_account_name: 1
  ip: 1
  malware_name: 2
  packagist_namespace: 1
updates:
  - at: "2026-07-06T13:14:26Z"
    level: L2
    summary: poc_available
    sources:
      - securityweek
  - at: "2026-07-07T13:08:18Z"
    level: L1
    summary: new product
    sources:
      - hackread
  - at: "2026-07-07T22:11:34Z"
    level: L1
    summary: OS windows
    sources:
      - unit42
  - at: "2026-07-16T08:52:23Z"
    level: L1
    summary: new IOCs
    sources:
      - any-run
    source_urls:
      - https://any.run/cybersecurity-blog/phantomenigma-research/
---

This brief tracks activity attributed to the ClickFix campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for ClickFix delivery
patterns across endpoint and network telemetry.
