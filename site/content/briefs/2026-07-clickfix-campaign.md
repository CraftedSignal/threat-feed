---
title: ClickFix Campaign Activity
slug: 2026-07-clickfix-campaign
description: Tracking brief for the ClickFix campaign; individual sightings are folded in as reported.
date: "2026-07-06T12:44:38Z"
lastmod: "2026-07-06T13:14:26Z"
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
products:
  - open source packages
  - GitHub repositories
  - NPM packages
  - Packagist packages
  - Go modules
  - Chrome extensions
references:
  - https://www.securityweek.com/north-korean-hackers-target-open-source-developers-in-supply-chain-attacks/
iocs:
  - type: github_account_name
    value: Xpos587
  - type: packagist_namespace
    value: sevenspan
  - type: malware_name
    value: DEV#POPPER
  - type: malware_name
    value: OmniStealer
ioc_counts:
  github_account_name: 1
  malware_name: 2
  packagist_namespace: 1
updates:
  - at: "2026-07-06T13:14:26Z"
    level: L2
    summary: poc_available
    sources:
      - securityweek
---

This brief tracks activity attributed to the ClickFix campaign. Sightings and
indicators from separate reports are folded in as they are published, rather
than creating a separate brief per report.

## Recommendation

Review the collected indicators and references and hunt for ClickFix delivery
patterns across endpoint and network telemetry.
