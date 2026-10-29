---
brief_id: brief-2026-10-29-extra-fees-injection
event_id: brief-2026-10-29-extra-fees-injection
revision: 1
activity_at: "2026-10-29T17:36:16Z"
title: 'Extra Fees Plugin for WooCommerce: PHP Object Injection (CVE-2026-116866)'
slug: 2026-10-extra-fees-injection
description: The Extra Fees Plugin for WooCommerce versions 4.4.0 and below contains a contributor-level PHP object injection vulnerability.
date: "2026-10-29T17:36:16Z"
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
tags:
  - web-vulnerability
  - php-injection
  - wordpress
products:
  - Extra Fees Plugin for WooCommerce (<= 4.4.0)
cves:
  - id: CVE-2026-116866
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116866
---

Extra Fees Plugin for WooCommerce versions 4.4.0 and earlier are vulnerable to a PHP object injection flaw that can be triggered by a contributor-level user.
