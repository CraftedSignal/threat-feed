---
brief_id: brief-2026-10-23-wpmobile-app-auth-bypass
event_id: brief-2026-10-23-wpmobile-app-auth-bypass
revision: 1
activity_at: "2026-10-23T09:35:13Z"
title: 'Amauri.IO WPMobile.App: Missing authorization vulnerability (CVE-2026-112359)'
slug: 2026-10-wpmobile-app-auth-bypass
description: The Amauri.IO WPMobile.App WordPress plugin contains a missing authorization vulnerability that allows for the exploitation of incorrectly configured access control security levels.
date: "2026-10-23T09:35:13Z"
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
  - cpe:2.3:a:amauri:wpmobile.app:*:*:*:*:*:wordpress:*:*
vendors:
  - Amauri.IO
products:
  - WPMobile.App (n/a through 11.86)
cves:
  - id: CVE-2026-112359
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112359
---

A missing authorization vulnerability exists in the Amauri.IO WPMobile.App WordPress plugin. The flaw permits the exploitation of incorrectly configured access control security levels. This issue affects WPMobile.App from n/a through 11.86.
