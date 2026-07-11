---
title: Shai-Hulud Campaign Activity
slug: 2026-07-shai-hulud-campaign
description: Tracking brief for the Shai-Hulud campaign; individual sightings are folded in as reported.
date: "2026-07-09T13:04:28Z"
lastmod: "2026-07-11T18:52:27Z"
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
affected_os:
  - Windows
  - macOS
  - Linux
references:
  - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
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
ioc_counts:
  domain: 2
  file: 4
  hash_sha256: 5
  ip: 2
  package: 1
updates:
  - at: "2026-07-11T18:52:27Z"
    level: L1
    summary: OS windows; OS macos; OS linux
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html
---

This brief tracks activity attributed to the Shai-Hulud campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for Shai-Hulud delivery
patterns across endpoint and network telemetry.
