---
brief_id: brief-2026-10-29-dedecms-code-injection-eff398ce
event_id: brief-2026-10-29-dedecms-code-injection-eff398ce
revision: 1
activity_at: "2026-10-29T21:23:46Z"
title: 'DedeCMS: Code injection via Advertisement Rendering (CVE-2026-116253)'
slug: 2026-10-dedecms-code-injection-eff398ce
description: A code injection vulnerability in DedeCMS 5.7.118 allows for remote exploitation via the aid parameter in the Advertisement Rendering component.
date: "2026-10-29T21:23:46Z"
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
  - cpe:2.3:a:dedecms:dedecms:*:*:*:*:*:*:*:*
vendors:
  - DedeCMS
products:
  - DedeCMS (5.7.118)
cves:
  - id: CVE-2026-116253
    cvss: 7.3
    epss: 0.00494
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116253
---

A vulnerability exists in DedeCMS 5.7.118 within the `common.inc.php::_RunMagicQuotes` function of the `plus/ad_js.php` file. The flaw affects the Advertisement Rendering component. Manipulating the `aid` argument can lead to code injection. The attack can be executed remotely.
