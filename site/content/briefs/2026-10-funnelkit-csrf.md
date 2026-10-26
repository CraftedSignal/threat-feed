---
brief_id: brief-2026-10-26-funnelkit-csrf
event_id: brief-2026-10-26-funnelkit-csrf
revision: 1
activity_at: "2026-10-26T09:41:03Z"
title: 'Aman FunnelKit Automations: Cross-Site Request Forgery (CVE-2026-111841)'
slug: 2026-10-funnelkit-csrf
description: A Cross-Site Request Forgery (CSRF) vulnerability exists in the Aman FunnelKit Automations WordPress plugin, affecting versions from n/a through 3.8.5.2.
date: "2026-10-26T09:41:03Z"
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
  - cpe:2.3:a:aman:funnelkit_automations:*:*:*:*:*:wordpress:*:*
vendors:
  - Aman
products:
  - FunnelKit Automations (<= 3.8.5.2)
cves:
  - id: CVE-2026-111841
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111841
---

A Cross-Site Request Forgery (CSRF) vulnerability has been identified in the Aman FunnelKit Automations WordPress plugin (wp-marketing-automations). This vulnerability affects plugin versions from n/a through 3.8.5.2. The vulnerability is assigned a CVSS v3.1 base score of 8.8.
