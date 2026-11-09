---
brief_id: brief-2026-11-09-welcart-xss
event_id: brief-2026-11-09-welcart-xss
revision: 1
activity_at: "2026-11-09T15:51:57Z"
title: 'Welcart e-Commerce: Stored Cross-site Scripting (CVE-2026-119505)'
slug: 2026-11-welcart-xss
description: The Welcart e-Commerce plugin for usc-e-shop is vulnerable to Stored Cross-site Scripting (XSS) due to improper neutralization of input during web page generation.
date: "2026-11-09T15:51:57Z"
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
  - cpe:2.3:a:welcart:e_commerce:*:*:*:*:*:*:*:*
vendors:
  - Welcart
products:
  - Welcart e-Commerce (usc-e-shop) up to 2.12.6
cves:
  - id: CVE-2026-119505
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119505
---

The Welcart e-Commerce plugin (usc-e-shop) contains an Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability. This vulnerability allows Stored XSS and affects versions from n/a through 2.12.6.
