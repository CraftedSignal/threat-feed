---
brief_id: brief-2026-10-21-gs-plugins-deserialization
event_id: brief-2026-10-21-gs-plugins-deserialization
revision: 1
activity_at: "2026-10-21T11:19:34Z"
title: 'GS Plugins WordPress Team Members: Deserialization of untrusted data (CVE-2026-110369)'
slug: 2026-10-gs-plugins-deserialization
description: The WordPress Team Members - GS Plugins plugin is affected by a Deserialization of Untrusted Data vulnerability, allowing Object Injection.
date: "2026-10-21T11:19:34Z"
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
  - cpe:2.3:a:gs_plugins:wordpress_team_members_gs_plugins:*:*:*:*:*:*:*:*
vendors:
  - GS Plugins
products:
  - WordPress Team Members – GS Plugins (n/a through 2.8.2)
cves:
  - id: CVE-2026-110369
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110369
---

The WordPress Team Members - GS Plugins plugin (versions n/a through 2.8.2) contains a Deserialization of Untrusted Data vulnerability. This flaw allows Object Injection.
