---
title: OpenClaw SSRF Vulnerability via Unguarded Configured Base URLs
slug: 2026-05-openclaw-ssrf
description: OpenClaw versions 2026.3.24 and earlier are vulnerable to Server-Side Request Forgery (SSRF) because of unguarded configured base URLs in multiple channel extensions, allowing attackers to potentially access internal resources.
date: "2026-03-29T15:49:23Z"
severities:
  - high
tags:
  - ssrf
  - openclaw
  - cve-2026-28476
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rhfg-j8jq-7v2h
rules:
  - title: Detect OpenClaw SSRF Vulnerable Versions
    description: Detects requests potentially originating from vulnerable OpenClaw versions based on user agent strings.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Outbound Connections to Internal IPs
    description: Detects outbound network connections from openclaw processes to private IP address ranges, which could indicate SSRF exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The `openclaw` package, a Node.js module, contains a Server-Side Request Forgery (SSRF) vulnerability in versions 2026.3.24 and earlier. This flaw stems from an incomplete fix for CVE-2026-28476, where several channel extensions continued to use raw `fetch()` against configured base URLs without proper SSRF protection. This omission allows attackers to potentially manipulate configured endpoints to target blocked internal destinations, bypassing intended security measures. The vulnerability was…
