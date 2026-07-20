---
title: Shai-Hulud Campaign Activity
slug: 2026-07-shai-hulud-campaign
description: Tracking brief for the Shai-Hulud campaign; individual sightings are folded in as reported.
date: "2026-07-09T13:04:28Z"
lastmod: "2026-07-20T13:12:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - campaign
  - shai-hulud
vendors:
  - Jscrambler
  - npm
  - Amazon
  - Microsoft
  - Google
  - MetaMask
  - Phantom
  - Exodus
  - Bitwarden
  - Discord
  - Slack
  - Telegram
  - Valve
  - Anthropic
  - Cursor
  - Windsurf
  - Zed
  - GitHub
  - AsyncAPI
  - Brave
  - Mozilla
products:
  - jscrambler 8.14.0
  - npm
  - AWS
  - Azure
  - Google Cloud
  - MetaMask
  - Phantom
  - Exodus
  - Bitwarden
  - Discord
  - Slack
  - Telegram
  - Steam
  - Claude Desktop
  - Cursor
  - Windsurf
  - VS Code
  - Zed
  - GitHub Actions
  - AsyncAPI Generator
  - '@asyncapi/generator (3.3.1)'
  - '@asyncapi/generator-helpers (1.1.1)'
  - '@asyncapi/generator-components (0.7.1)'
  - '@asyncapi/specs (6.11.2)'
  - '@asyncapi/specs (6.11.2-alpha.1)'
  - Chrome
  - Brave
  - Firefox
  - Edge
  - macOS Keychain
  - GitHub
affected_os:
  - Windows
  - macOS
  - Linux
references:
  - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
  - https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions
  - https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/impact_high_number_of_protected_branch_force_pushes_by_user.toml
iocs:
  - type: package
    value: jscrambler@8.14.0
  - type: hash_sha256
    value: a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60
  - type: hash_sha256
    value: a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86
  - type: hash_sha256
    value: fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd
  - type: hash_sha256
    value: b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903
  - type: hash_sha256
    value: c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd
  - type: ip
    value: 37.27.122.124
  - type: ip
    value: 57.128.246.79
  - type: domain
    value: check.torproject.org
  - type: domain
    value: archive.torproject.org
  - type: file
    value: .{random}
  - type: file
    value: .{random}.exe
  - type: file
    value: ~/Library/LaunchAgents/*
  - type: file
    value: Windows Scheduled Task
  - type: ip
    value: 85.137.53.71
  - type: domain
    value: ipfs.io
  - type: domain
    value: rentry.co
ioc_counts:
  domain: 4
  file: 4
  hash_sha256: 5
  ip: 3
  package: 1
updates:
  - at: "2026-07-11T18:52:27Z"
    level: L1
    summary: OS windows; OS macos; OS linux
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
  - at: "2026-07-14T10:49:09Z"
    level: L2
    summary: poc_available
    sources:
      - wiz
    source_urls:
      - https://www.wiz.io/blog/m-red-team-asyncapi-supply-chain-compromise-via-github-actions
  - at: "2026-07-15T09:41:39Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/compromised-asyncapi-npm-packages.html
  - at: "2026-07-20T13:12:56Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/github/impact_high_number_of_protected_branch_force_pushes_by_user.toml
---

This brief tracks activity attributed to the Shai-Hulud campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for Shai-Hulud delivery
patterns across endpoint and network telemetry.
