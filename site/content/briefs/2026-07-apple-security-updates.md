---
title: Apple Security Updates — July 2026
slug: 2026-07-apple-security-updates
description: Roundup of Apple security advisories published in July 2026.
date: "2026-07-03T13:48:34Z"
lastmod: "2026-07-13T09:40:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - roundup
vendors:
  - Apple
products:
  - macOS LaunchAgents
  - macOS LaunchDaemons
  - macOS
  - iOS (>= 17)
  - CUPS
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
iocs:
  - type: url
    value: https://github.com/F4R3SX0/iOS-Bluetooth-Ethernet-Exploit
ioc_counts:
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
---

Aggregated Apple security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Apple's July 2026 security updates.
