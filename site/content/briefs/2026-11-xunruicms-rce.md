---
brief_id: brief-2026-11-02-xunruicms-rce
event_id: brief-2026-11-02-xunruicms-rce
revision: 1
activity_at: "2026-11-02T07:17:34Z"
title: 'XunRuiCMS: Remote code injection in Email Template Rendering (CVE-2026-120348)'
slug: 2026-11-xunruicms-rce
description: XunRuiCMS versions up to 4.7.4 are vulnerable to code injection via the _get_tpl_content function in the Email Template Rendering component.
date: "2026-11-02T07:17:34Z"
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
  - cpe:2.3:a:dayrui:xunruicms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - rce
  - vulnerability
vendors:
  - dayrui
products:
  - XunRuiCMS (<= 4.7.4)
cves:
  - id: CVE-2026-120348
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120348
---

A vulnerability exists in dayrui XunRuiCMS up to 4.7.4. The function _get_tpl_content in dayrui/Fcms/Library/Notice.php (Email Template Rendering component) is susceptible to code injection. The attack can be initiated remotely. Public exploit code is available. The vendor was contacted but did not respond. The CVSS v3.1 base score is 7.3.
