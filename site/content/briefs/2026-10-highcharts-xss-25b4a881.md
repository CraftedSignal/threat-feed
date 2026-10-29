---
brief_id: brief-2026-10-29-highcharts-xss-25b4a881
event_id: brief-2026-10-29-highcharts-xss-25b4a881
revision: 3
activity_at: "2026-10-29T12:29:28Z"
revision_history:
  - revision: 2
    at: "2026-10-29T06:15:43Z"
    checksum: sha256:9a9f7b796e8e158203fb28bd7192fc9eb68cdea3c98d08229b3b1c49d7b73895
    summary: added CVE-2026-118244
    changed_fields:
      - affected_products
      - cves
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-65hg-cf3f-5m39
  - revision: 3
    at: "2026-10-29T12:29:28Z"
    checksum: sha256:f79addfb6c3766b161bda0b284ec1c8e298cac7d88eb7b585e0bcee681a8fff5
    summary: added coverage for Highcharts (6.1.0 - 13.0.2)
    changed_fields:
      - action_plan
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - lastmod
      - qa_status
      - references
      - ttps
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-gfvx-2c2g-38wq
title: 'Highcharts: Cross-site scripting in exported SVG files (CVE-2026-116796)'
slug: 2026-10-highcharts-xss-25b4a881
description: Highcharts fails to sanitize 'xlink:href' attributes in SVG text options, allowing 'javascript:' URIs to be preserved in exported charts.
date: "2026-10-29T00:17:20Z"
lastmod: "2026-10-29T12:28:11Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified; no environment validation required.
cpes:
  - cpe:2.3:a:highcharts:highcharts:*:*:*:*:*:*:*:*
vendors:
  - Highcharts
products:
  - Highcharts (npm/highcharts 10.3.2 - 11.4.9)
  - Highcharts (npm/highcharts 12.0.0 - 12.6.2)
  - Highcharts (npm/highcharts 13.0.0 - 13.1.0)
  - Highcharts (npm/highcharts >= 12.0.0, < 12.6.1)
  - Highcharts (npm/highcharts >= 13.0.0, <= 13.0.2)
  - Highcharts (6.1.0 - 13.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.007
    subtechnique_name: JavaScript
    evidence: Attackers providing specially crafted point objects containing '__proto__' or 'constructor' keys can inject properties into the global Object.prototype.
    confidence_band: high
cves:
  - id: CVE-2026-116796
    kev_status: "false"
  - id: CVE-2026-118244
    kev_status: "false"
  - id: CVE-2026-118249
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-mw4f-gj5x-6xr4
  - https://github.com/advisories/GHSA-65hg-cf3f-5m39
  - https://github.com/advisories/GHSA-gfvx-2c2g-38wq
  - https://jsfiddle.net/BlackLabel/nopc6vhj/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Development
  immediate_actions:
    - action: Upgrade Highcharts to version 13.1.0 or later
      owner: Web Development
      due: 48h
      evidence: The patched releases are available from all the usual distribution channels.
  hunt_leads:
    - lead: Identify applications utilizing Highcharts versions 6.1.0-13.0.2 that parse external/user-controlled JSON as series point objects.
      technique_id: T1059.007
      data_needed:
        - Application dependency inventory
        - Runtime JS error logs (searching for unexpected prototype properties)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers who control the point objects can set integer-keyed properties on Object.prototype.
  mitigation_plan:
    - priority: immediate
      action: Apply the JavaScript IIFE patch to sanitize point object inputs
      owner: Web Development
      addresses: CVE-2026-118249
      evidence: Drop-in fix - for any versions affected (6.1.0-13.0.2).
updates:
  - at: "2026-10-29T06:13:36Z"
    level: L2
    summary: added CVE-2026-118244
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-65hg-cf3f-5m39
  - at: "2026-10-29T12:28:11Z"
    level: L2
    summary: added coverage for Highcharts (6.1.0 - 13.0.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gfvx-2c2g-38wq
---

Highcharts contains an XSS vulnerability (CVE-2026-116796) where the SVG exporting module fails to sanitize 'xlink:href' attributes in text options. The attribute is preserved in the serialized output of exported charts. If a user activates a link within an exported SVG opened in a browser or re-parsed in a downstream application, an attacker who controls the chart configuration can execute script in the origin of that document.
