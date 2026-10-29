---
brief_id: brief-2026-10-29-highcharts-xss-25b4a881
event_id: brief-2026-10-29-highcharts-xss-25b4a881
revision: 1
activity_at: "2026-10-29T00:17:20Z"
title: 'Highcharts: Cross-site scripting in exported SVG files (CVE-2026-116796)'
slug: 2026-10-highcharts-xss-25b4a881
description: Highcharts fails to sanitize 'xlink:href' attributes in SVG text options, allowing 'javascript:' URIs to be preserved in exported charts.
date: "2026-10-29T00:17:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - Highcharts (npm/highcharts 10.3.2 - 11.4.9)
  - Highcharts (npm/highcharts 12.0.0 - 12.6.2)
  - Highcharts (npm/highcharts 13.0.0 - 13.1.0)
cves:
  - id: CVE-2026-116796
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-mw4f-gj5x-6xr4
---

Highcharts contains an XSS vulnerability (CVE-2026-116796) where the SVG exporting module fails to sanitize 'xlink:href' attributes in text options. The attribute is preserved in the serialized output of exported charts. If a user activates a link within an exported SVG opened in a browser or re-parsed in a downstream application, an attacker who controls the chart configuration can execute script in the origin of that document.
