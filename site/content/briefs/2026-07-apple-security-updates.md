---
title: Apple Security Updates — July 2026
slug: 2026-07-apple-security-updates
description: Roundup of Apple security advisories published in July 2026.
date: "2026-07-03T13:48:34Z"
lastmod: "2026-07-13T18:02:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Apple
  - Google
  - Brave Software
  - Microsoft
  - Opera
  - Vivaldi Technologies
  - Naver
  - MetaMask
  - Phantom
  - Coinbase
  - Trust Wallet
  - Rabby
  - OKX Wallet
  - Exodus
  - Keplr
  - Solfare
  - Backpack
  - AgileBits
  - Bitwarden
  - LastPass
  - Dashlane
  - Keeper Security
  - KeePassXC
  - NordPass
  - Enpass
  - RoboForm
products:
  - macOS LaunchAgents
  - macOS LaunchDaemons
  - macOS
  - iOS (>= 17)
  - CUPS
  - Google Chrome
  - Brave
  - Microsoft Edge
  - Opera
  - Opera GX
  - Vivaldi
  - Chromium
  - Naver Whale
  - MetaMask
  - Phantom
  - Coinbase Wallet
  - Trust Wallet
  - Rabby Wallet
  - OKX Wallet
  - Exodus Wallet
  - Keplr Wallet
  - Solfare Wallet
  - Backpack Wallet
  - 1Password
  - Bitwarden
  - LastPass
  - Dashlane
  - Keeper
  - KeePassXC
  - NordPass
  - Enpass
  - RoboForm
affected_os:
  - macOS
  - iOS 17
  - iOS 17.5.1
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_suspicious_launch_agent_or_launch_daemon.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/lateral_movement_remote_ssh_login_enabled.toml
  - https://www.reddit.com/r/blueteamsec/comments/1un3vp2/pamstealer_a_rustbased_macos_infostealer_that/
  - https://www.exploit-db.com/exploits/52618
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2282
  - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
iocs:
  - type: url
    value: https://github.com/F4R3SX0/iOS-Bluetooth-Ethernet-Exploit
  - type: domain
    value: werkbit.io
  - type: ip
    value: 179.43.166.242
  - type: filename
    value: Werkbit.app
  - type: filename
    value: veltod
  - type: filename
    value: sys.cache
  - type: filename
    value: CrashReporter.dmg
  - type: other
    value: Emil Grigorov (WWB7JA7AQV)
ioc_counts:
  domain: 1
  filename: 4
  ip: 1
  other: 1
  url: 1
updates:
  - at: "2026-07-03T15:42:59Z"
    level: L1
    summary: OS macos
    sources:
      - elastic
  - at: "2026-07-04T09:00:46Z"
    level: L1
    summary: new product
    sources:
      - reddit-blueteamsec
  - at: "2026-07-07T13:27:17Z"
    level: L1
    summary: OS ios 17.5.1; OS ios 17
    sources:
      - exploit-db
  - at: "2026-07-13T09:40:00Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2282
  - at: "2026-07-13T18:02:11Z"
    level: L1
    summary: new IOCs
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
---

Aggregated Apple security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Apple's July 2026 security updates.
