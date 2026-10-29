---
brief_id: brief-2026-10-29-highcharts-dashboards-xss
event_id: brief-2026-10-29-highcharts-dashboards-xss
revision: 2
activity_at: "2026-10-29T19:50:13Z"
revision_history:
  - revision: 2
    at: "2026-10-29T19:50:13Z"
    checksum: sha256:7cff65f64c5072284e326321334eecef6d03d301f0e49bc4add91bf56f7ffeb8
    summary: added coverage for Highcharts Dashboards (>= 1.0.0, <= 4.2.2)
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-rcqf-f6h2-ccg9
title: 'Highcharts Dashboards: Cross-Site Scripting via Fullscreen Labels'
slug: 2026-10-highcharts-dashboards-xss
description: Highcharts Dashboards parses fullscreen labels as HTML, allowing an attacker who controls the Dashboards language options to execute script in the origin of the page hosting the dashboard.
date: "2026-10-29T06:13:04Z"
lastmod: "2026-10-29T19:49:22Z"
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
  - cpe:2.3:a:highcharts:highcharts_dashboards:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
vendors:
  - Highcharts
products:
  - 'Highcharts Dashboards (vulnerable: >= 1.0.0, < 4.2.3)'
  - Highcharts Dashboards (>= 1.0.0, <= 4.2.2)
cves:
  - id: CVE-2026-118253
    kev_status: "false"
  - id: CVE-2026-118252
    epss: 0.00419
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-58g7-7f52-h92c
  - https://github.com/advisories/GHSA-rcqf-f6h2-ccg9
  - https://www.highcharts.com/docs/dashboards/installation
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Application Security
  immediate_actions:
    - action: Upgrade Highcharts Dashboards to version 4.2.3 or later
      owner: IT Operations
      due: 48h
      evidence: The patched releases are available from all the usual distribution channels.
  hunt_leads:
    - lead: Identify applications utilizing Highcharts Dashboards
      data_needed:
        - Application dependency manifests (package.json)
        - Client-side library loads
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'Affected Packages: npm/@highcharts/dashboards (vulnerable: >= 1.0.0, <= 4.2.2)'
  mitigation_plan:
    - priority: immediate
      action: Apply the JavaScript sanitization patch to EditMode or disable EditMode if unused
      owner: Web Application Security
      addresses: CVE-2026-118252
      evidence: Until you can upgrade, patch EditMode once at application startup.
updates:
  - at: "2026-10-29T19:49:22Z"
    level: L2
    summary: added coverage for Highcharts Dashboards (>= 1.0.0, <= 4.2.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-rcqf-f6h2-ccg9
---

Highcharts Dashboards edit mode fullscreen labels are parsed as HTML when the corresponding control is rendered. If an attacker controls the Dashboards language options, they can supply markup carrying event handlers. These execute in the origin of the page hosting the dashboard, gaining access to page data, storage, and session state.

## Impact
Successful exploitation allows script execution with the same access to page data, storage, and session state as the hosting application. Exploitation requires that untrusted data reach the Dashboards language configuration and that the affected control be rendered.
