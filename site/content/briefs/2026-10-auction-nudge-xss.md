---
brief_id: brief-2026-10-29-auction-nudge-xss
event_id: brief-2026-10-29-auction-nudge-xss
revision: 1
activity_at: "2026-10-29T17:39:54Z"
title: 'Auction Nudge: Unauthenticated Cross Site Scripting (CVE-2026-61988)'
slug: 2026-10-auction-nudge-xss
description: Auction Nudge - Your eBay on Your Site versions 8.4.0 and earlier contain an unauthenticated Cross Site Scripting (XSS) vulnerability.
date: "2026-10-29T17:39:54Z"
type: advisory
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
  - cpe:2.3:a:auction_nudge:your_ebay_on_your_site:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - Auction Nudge
products:
  - Auction Nudge – Your eBay on Your Site (<= 8.4.0)
cves:
  - id: CVE-2026-61988
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61988
---

The Auction Nudge - Your eBay on Your Site plugin, versions 8.4.0 and earlier, is affected by an unauthenticated Cross Site Scripting (XSS) vulnerability. The CVSS v3.1 base score for this vulnerability is 7.1.
