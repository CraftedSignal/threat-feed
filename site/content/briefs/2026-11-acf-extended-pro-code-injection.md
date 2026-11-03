---
brief_id: brief-2026-11-03-acf-extended-pro-code-injection
event_id: brief-2026-11-03-acf-extended-pro-code-injection
revision: 1
activity_at: "2026-11-03T05:54:31Z"
title: 'Advanced Custom Fields: Extended PRO: Limited Code Injection (CVE-2026-120534)'
slug: 2026-11-acf-extended-pro-code-injection
description: 'The Advanced Custom Fields: Extended PRO plugin for WordPress is vulnerable to Limited Code Injection via the render_field function.'
date: "2026-11-03T05:54:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:advancedcustomfields:extended_pro:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - vulnerability
vendors:
  - Advanced Custom Fields
products:
  - 'Advanced Custom Fields: Extended PRO (<= 0.9.2.6)'
cves:
  - id: CVE-2026-120534
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120534
---

CVE-2026-120534 identifies a vulnerability in Advanced Custom Fields: Extended PRO for WordPress in all versions up to, and including, 0.9.2.6. The flaw exists in the 'render_field' function due to insufficient validation of form configuration parameters before they are merged into field settings and passed to 'call_user_func_array'. 

This vulnerability allows unauthenticated attackers to call arbitrary WordPress functions with controlled arguments, contingent on specific conditions:
1. The administrator has enabled the non-default 'shortcode_preview' setting for the target form.
2. The server environment lacks OpenSSL functions, causing 'acf_decrypt' to fall back to unverified base64 decoding.
