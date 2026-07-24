---
title: ClickFix Campaign Activity
slug: 2026-07-clickfix-campaign
description: Tracking brief for the ClickFix campaign; individual sightings are folded in as reported.
date: "2026-07-06T12:44:38Z"
lastmod: "2026-07-24T16:21:05Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
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
  - Apple
  - Zoom
  - Calendly
  - Brave
  - Mozilla
  - Opera
  - Vivaldi
  - MetaMask
  - OpenAI
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
  - macOS
  - Zoom
  - Microsoft Teams
  - Calendly
  - Telegram Web
  - Telegram Desktop
  - Google Chrome
  - Microsoft Edge
  - Brave
  - Mozilla Firefox
  - Opera
  - Opera GX
  - Vivaldi
  - MetaMask
  - iCloud Keychain
  - Microsoft Defender
  - OpenAI ChatGPT
affected_os:
  - Windows
  - macOS
references:
  - https://www.securityweek.com/north-korean-hackers-target-open-source-developers-in-supply-chain-attacks/
  - https://hackread.com/gitlost-github-ai-agent-leaking-repository-data/
  - https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/
  - https://www.reddit.com/r/blueteamsec/comments/1uxuh7t/telepuz_a_modular_maas_malware_spreading_via/
  - https://any.run/cybersecurity-blog/phantomenigma-research/
  - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
  - https://www.securityweek.com/clicklock-stealer-bypasses-macos-security-with-social-engineering-process-killing/
  - https://thehackernews.com/2026/07/bluenoroff-zoom-phishing-kit-profiles.html
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
  - type: domain
    value: us.zoom.06webin.us
  - type: telegram handle
    value: '@alchemy_john_mac'
  - type: telegram channel
    value: Aurora
ioc_counts:
  domain: 5
  github_account_name: 1
  ip: 1
  malware_name: 2
  packagist_namespace: 1
  telegram channel: 1
  telegram handle: 1
updates:
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
  - at: "2026-07-16T10:01:31Z"
    level: L2
    summary: poc_available
    sources:
      - talos
    source_urls:
      - https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/
  - at: "2026-07-16T12:45:34Z"
    level: L1
    summary: OS macos
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/clicklock-stealer-bypasses-macos-security-with-social-engineering-process-killing/
  - at: "2026-07-24T16:21:05Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/bluenoroff-zoom-phishing-kit-profiles.html
---

This brief tracks activity attributed to the ClickFix campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for ClickFix delivery
patterns across endpoint and network telemetry.
