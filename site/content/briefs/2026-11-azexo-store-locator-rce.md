---
brief_id: brief-2026-11-09-azexo-store-locator-rce
event_id: brief-2026-11-09-azexo-store-locator-rce
revision: 1
activity_at: "2026-11-09T19:56:37Z"
title: 'AZEXO Store Locator: Arbitrary file write and remote code execution (CVE-2026-115204)'
slug: 2026-11-azexo-store-locator-rce
description: The AZEXO Store Locator WordPress plugin through 1.4 fails to perform capability or nonce checks on AJAX actions and lacks sanitization of request headers used for file path construction, allowing authenticated users to perform arbitrary file writes leading to remote code execution.
date: "2026-11-09T19:56:37Z"
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
  - cpe:2.3:a:azexo:store_locator:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - plugin
  - rce
  - cve-2026-115204
vendors:
  - AZEXO
products:
  - Store Locator (<= 1.4)
cves:
  - id: CVE-2026-115204
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115204
---

The AZEXO Store Locator WordPress plugin through 1.4 does not perform capability or nonce checks on its AJAX actions and does not sanitise a request header used to build a file path. This allows an authenticated user, such as a subscriber, to write a file with an arbitrary name, location, and content, leading to remote code execution.
