---
brief_id: brief-2026-11-09-beikeshop-order-repo
event_id: brief-2026-11-09-beikeshop-order-repo
revision: 2
activity_at: "2026-11-09T09:25:54Z"
revision_history:
  - revision: 2
    at: "2026-11-09T09:25:54Z"
    checksum: sha256:c48d382a13cb2a4207936000b773ce8d1ea7c436e53ef57620b88c951b9b9b45
    summary: poc_available
    changed_fields:
      - affected_vendors
      - claim_state
      - cpes
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-124576&utm_source=rss&utm_medium=rss
title: 'BeikeShop: Guest Order Lookup parameter manipulation (CVE-2026-124576)'
slug: 2026-11-beikeshop-order-repo
description: A security flaw in BeikeShop up to 2.0.0.31 in the Guest Order Lookup feature allows for remote manipulation of the order_number argument.
date: "2026-11-09T07:32:03Z"
lastmod: "2026-11-09T09:25:13Z"
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
  - cpe:2.3:a:beikeshop:beikeshop:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-124576&utm_source=rss&utm_medium=rss
tags:
  - web-vulnerability
  - cve-2026-124576
vendors:
  - BeikeShop
products:
  - BeikeShop (<= 2.0.0.31)
cves:
  - id: CVE-2026-124576
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124576
  - https://sploitus.com/exploit?id=CVE-2026-124576&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-09T09:25:13Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-124576&utm_source=rss&utm_medium=rss
---

A security flaw has been discovered in BeikeShop up to 2.0.0.31. The vulnerability exists in the `OrderRepo::getOrderByNumber` function within `beike/Repositories/OrderRepo.php` of the Guest Order Lookup component. Manipulation of the `order_number` argument results in the enforcement of behavioral workflow. The attack can be initiated remotely.
