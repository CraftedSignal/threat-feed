---
title: Malware Spreading Through Fake 'Claude Code' Google Ads
slug: 2024-01-03-fake-claude-ads
description: Malware is distributed via malicious advertisements on Google impersonating 'Claude Code', targeting both Windows and macOS operating systems with the goal of infecting users.
date: "2026-03-15T15:31:12Z"
severities:
  - high
tags:
  - malware
  - google_ads
  - initial_access
  - windows
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ruh0r8/windows_and_macos_malware_spreads_via_fake_claude/
  - https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware
rules:
  - title: Detect Web Requests to Sites with Claude in the Domain
    description: Detects web requests to domains containing 'claude' which may indicate malicious activity related to the Claude code malware campaign.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - web_proxy
      - windows|linux|macos
  - title: Detect Execution of Downloaded Files from Suspicious Domains
    description: Detects execution of files downloaded from domains potentially associated with the Claude code malware campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A malware campaign is underway, leveraging deceptive advertisements on Google that masquerade as legitimate 'Claude Code' software. The attackers are using these ads to direct unsuspecting users to malicious websites hosting malware payloads for both Windows and macOS systems. While specific details on the malware are limited, the campaign's reliance on search engine advertisement poisoning indicates a broad targeting strategy aimed at users actively seeking 'Claude Code' related software or…
