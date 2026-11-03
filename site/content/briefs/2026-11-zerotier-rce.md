---
brief_id: brief-2026-11-03-zerotier-rce
event_id: brief-2026-11-03-zerotier-rce
revision: 2
activity_at: "2026-11-03T12:09:52Z"
revision_history:
  - revision: 2
    at: "2026-11-03T12:09:52Z"
    checksum: sha256:20bfb72638d38f0929f50ba9c751c58faafea5bbde4229c73a33394990063043
    summary: poc_available
    changed_fields:
      - affected_products
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-105979&utm_source=rss&utm_medium=rss
title: 'ZeroTier: Command injection via improper input validation (CVE-2026-105979)'
slug: 2026-11-zerotier-rce
description: An improper input validation vulnerability in the ZeroTier VPN function allows a remote attacker with high privileges to inject and execute system commands with root privileges.
date: "2026-11-03T09:56:54Z"
lastmod: "2026-11-03T12:09:12Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:zerotier:vpn:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-105979&utm_source=rss&utm_medium=rss
vendors:
  - ZeroTier
products:
  - ZeroTier VPN
cves:
  - id: CVE-2026-105979
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105979
  - https://sploitus.com/exploit?id=CVE-2026-105979&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T12:09:12Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-105979&utm_source=rss&utm_medium=rss
---

Improper input validation in the ZeroTier VPN function may allow a remote attacker with high privileges to inject system commands and execute them with root privileges. The CVSS v3.1 Base Score for this vulnerability is 7.2.
