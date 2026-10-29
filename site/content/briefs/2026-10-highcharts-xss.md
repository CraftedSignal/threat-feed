---
brief_id: brief-2026-10-29-highcharts-xss
event_id: brief-2026-10-29-highcharts-xss
revision: 1
activity_at: "2026-10-29T00:16:40Z"
title: 'Highcharts Core: Breadcrumbs style attribute cross-site scripting (CVE-2026-118246)'
slug: 2026-10-highcharts-xss
description: A cross-site scripting (XSS) vulnerability in Highcharts Core allows arbitrary JavaScript execution when an attacker-controlled chart configuration injects event-handler attributes into SVG breadcrumb elements.
date: "2026-10-29T00:16:40Z"
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
  validation_status: Needs environment validation for the workaround snippet.
cpes:
  - cpe:2.3:a:highcharts:highcharts:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-application
  - client-side-injection
vendors:
  - Highcharts
products:
  - Highcharts Core (>= 10.0.0, < 11.4.9)
  - Highcharts Core (>= 12.0.0, < 12.6.1)
  - Highcharts Core (>= 13.0.0, <= 13.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: An attacker who controls the chart configuration can supply keys under breadcrumbs.style that name event handlers, and those keys become live handlers on the breadcrumb button, so the attacker's script runs in the origin of the page hosting the chart.
    confidence_band: high
cves:
  - id: CVE-2026-118246
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-35rr-xwfh-x789
  - https://code.highcharts.com
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Development
  immediate_actions:
    - action: Patch Highcharts to versions 11.4.9, 12.6.1, or 13.1.0.
      owner: IT Operations
      due: 48h
      evidence: Obtaining the patched version section identifies these versions as providing the fix.
  hunt_leads:
    - lead: Scan web application traffic or backend logs for user-supplied JSON payloads containing 'breadcrumbs' configuration objects with suspicious keys (e.g., 'onmouseover', 'onclick', 'onerror').
      technique_id: T1059.007
      data_needed:
        - HTTP POST payloads
        - JSON configuration blobs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An attacker who controls the chart configuration can supply keys under breadcrumbs.style that name event handlers.
  mitigation_plan:
    - priority: immediate
      action: Deploy JavaScript workaround snippet in production environment if patching is delayed.
      owner: Web Development
      addresses: CVE-2026-118246
      evidence: Workarounds section provides specific remediation logic.
---

Highcharts Core versions 10.0.0 through 13.0.2 are affected by a cross-site scripting (XSS) vulnerability identified as CVE-2026-118246. The `breadcrumbs.style` configuration option fails to sanitize keys before applying them as SVG attributes. An attacker capable of influencing the chart configuration can inject event-handler attributes, such as `onmouseover`, which the browser will execute in the context of the origin hosting the chart when the breadcrumb component is rendered and interacted with by a user. This flaw affects Highcharts Core, Highcharts Stock, Highcharts Maps, and Highcharts Gantt. Charts utilizing "styled mode" are not affected.

## Impact
Successful exploitation leads to arbitrary JavaScript execution in the user's browser session. This can be used to hijack user sessions, steal sensitive data, or perform unauthorized actions on behalf of the user within the vulnerable application origin.

## Recommendation
- Upgrade Highcharts to the patched versions: 11.4.9, 12.6.1, or 13.1.0 or later.
- If upgrading is not immediately feasible, apply the provided JavaScript workaround by injecting the following snippet after loading the Highcharts library but before any chart initialization:
 `((H)=>{const S=H.SVGElement.prototype,D=S._defaultSetter;S._defaultSetter=function _defaultSetter(v,k,e){/^on/i.test(k)||D.call(this,v,k,e)};})(Highcharts);`
- Audit applications that pass user-supplied or external JSON configuration objects to Highcharts to ensure the `breadcrumbs` configuration object is strictly validated against a known-safe schema.
