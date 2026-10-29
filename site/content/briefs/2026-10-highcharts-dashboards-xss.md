---
brief_id: brief-2026-10-29-highcharts-dashboards-xss
event_id: brief-2026-10-29-highcharts-dashboards-xss
revision: 1
activity_at: "2026-10-29T06:13:04Z"
title: 'Highcharts Dashboards: Cross-Site Scripting via Fullscreen Labels'
slug: 2026-10-highcharts-dashboards-xss
description: Highcharts Dashboards parses fullscreen labels as HTML, allowing an attacker who controls the Dashboards language options to execute script in the origin of the page hosting the dashboard.
date: "2026-10-29T06:13:04Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified.
cpes:
  - cpe:2.3:a:highcharts:dashboards:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - Highcharts
products:
  - 'Highcharts Dashboards (vulnerable: >= 1.0.0, < 4.2.3)'
cves:
  - id: CVE-2026-118253
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-58g7-7f52-h92c
---

Highcharts Dashboards edit mode fullscreen labels are parsed as HTML when the corresponding control is rendered. If an attacker controls the Dashboards language options, they can supply markup carrying event handlers. These execute in the origin of the page hosting the dashboard, gaining access to page data, storage, and session state.

## Impact
Successful exploitation allows script execution with the same access to page data, storage, and session state as the hosting application. Exploitation requires that untrusted data reach the Dashboards language configuration and that the affected control be rendered.
