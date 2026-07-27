---
title: Apple Security Updates — July 2026
slug: 2026-07-apple-security-updates
description: Roundup of Apple security advisories published in July 2026.
date: "2026-07-03T13:48:34Z"
lastmod: "2026-07-27T20:04:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:apple:mac_os_x:-:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ios:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hp:hp-ux:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hp:tru64:-:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:aix:-:*:*:*:*:*:*:*
  - cpe:2.3:o:ibm:os2:-:*:*:*:*:*:*:*
  - cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*
  - cpe:2.3:o:novell:netware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:oracle:solaris:-:*:*:*:*:*:-:*
  - cpe:2.3:o:sco:sco_unix:-:*:*:*:*:*:*:*
  - cpe:2.3:o:sgi:irix:-:*:*:*:*:*:*:*
  - cpe:2.3:o:windriver:bsdos:-:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=379FFFB3-48FB-5D0C-92C2-23B434647F8D&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=2C60D315-2B9E-5345-A2A8-F702C037CF66&utm_source=rss&utm_medium=rss
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
  - Cisco
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
  - Mac_Os_X
  - IOS
  - ASA
  - Windows
  - macOS Sequoia
  - macOS Sonoma
  - macOS Ventura
  - macOS Sonoma (< 14.8.8)
  - macOS Sequoia (< 15.7.8)
  - macOS Tahoe (< 26.6)
affected_os:
  - macOS
  - iOS 17
  - iOS 17.5.1
  - Linux
  - Windows
  - macOS Sequoia
  - macOS Sonoma
  - macOS Ventura
  - macOS Tahoe
cves:
  - id: CVE-1999-0524
    cvss: 4
    epss: 0.31586
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/persistence_suspicious_launch_agent_or_launch_daemon.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/lateral_movement_remote_ssh_login_enabled.toml
  - https://www.reddit.com/r/blueteamsec/comments/1un3vp2/pamstealer_a_rustbased_macos_infostealer_that/
  - https://www.exploit-db.com/exploits/52618
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2282
  - https://thehackernews.com/2026/07/crashstealer-macos-malware-uses.html
  - https://sploitus.com/exploit?id=379FFFB3-48FB-5D0C-92C2-23B434647F8D&utm_source=rss&utm_medium=rss
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1672
  - https://sploitus.com/exploit?id=2C60D315-2B9E-5345-A2A8-F702C037CF66&utm_source=rss&utm_medium=rss
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
  - type: url
    value: https://sploitus.com/exploit?id=379FFFB3-48FB-5D0C-92C2-23B434647F8D
  - type: url
    value: https://sploitus.com/exploit?id=2C60D315-2B9E-5345-A2A8-F702C037CF66
ioc_counts:
  domain: 1
  filename: 4
  ip: 1
  other: 1
  url: 3
updates:
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
  - at: "2026-07-14T08:04:07Z"
    level: L2
    summary: poc_available; added CVE-1999-0524; OS linux; OS windows
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=379FFFB3-48FB-5D0C-92C2-23B434647F8D&utm_source=rss&utm_medium=rss
  - at: "2026-07-15T06:42:32Z"
    level: L1
    summary: OS macos sequoia; OS macos sonoma; OS macos ventura
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1672
  - at: "2026-07-27T20:04:45Z"
    level: L2
    summary: macos sequoia version < 15.7.8; macos sonoma version < 14.8.8; OS macos tahoe
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=2C60D315-2B9E-5345-A2A8-F702C037CF66&utm_source=rss&utm_medium=rss
---

Aggregated Apple security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Apple's July 2026 security updates.
