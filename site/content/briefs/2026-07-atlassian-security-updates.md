---
title: Atlassian Security Updates — July 2026
slug: 2026-07-atlassian-security-updates
description: Roundup of Atlassian security advisories published in July 2026.
date: "2026-07-10T10:02:54Z"
lastmod: "2026-07-22T17:36:45Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
tags:
  - roundup
vendors:
  - Atlassian
  - mcp-atlassian
products:
  - mcp-atlassian < 0.22.0
  - Confluence
  - Jira
  - Atlassian Bamboo
  - Bitbucket
  - Fisheye
  - Crucible
  - Jira Service Management
  - Bamboo Data Center and Server
  - Bitbucket Data Center and Server
  - Confluence Data Center and Server
  - Crowd Data Center and Server
  - Fisheye/Crucible (4.9.0 to 4.9.11)
  - Jira Data Center and Server
  - Jira Service Management Data Center and Server
  - Sourcetree (3.4.11 to 3.4.12)
affected_os:
  - Windows
  - Linux
  - macOS
references:
  - https://github.com/advisories/GHSA-g5r6-gv6m-f5jv
  - https://github.com/advisories/GHSA-wm45-qh3g-v83f
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2460
  - https://cyber.gc.ca/en/alerts-advisories/atlassian-security-advisory-av26-731
updates:
  - at: "2026-07-10T19:46:37Z"
    level: L2
    summary: poc_available; OS windows; OS linux
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-g5r6-gv6m-f5jv
  - at: "2026-07-10T19:47:09Z"
    level: L1
    summary: new product
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-wm45-qh3g-v83f
  - at: "2026-07-22T10:23:36Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2460
  - at: "2026-07-22T17:36:45Z"
    level: L1
    summary: OS macos
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/atlassian-security-advisory-av26-731
---

Aggregated Atlassian security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Atlassian's July 2026 security updates.
