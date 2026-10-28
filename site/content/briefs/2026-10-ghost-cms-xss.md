---
brief_id: brief-2026-10-28-ghost-cms-xss
event_id: brief-2026-10-28-ghost-cms-xss
revision: 1
activity_at: "2026-10-28T20:23:50Z"
title: 'Ghost CMS: Stored XSS and privilege escalation (CVE-2025-66849)'
slug: 2026-10-ghost-cms-xss
description: A public exploit for CVE-2025-66849 has been published. The vulnerability is a stored XSS in the Ghost CMS HTML block that allows a Contributor to perform unauthorized actions by executing JavaScript in the context of an Owner account.
date: "2026-10-28T20:23:50Z"
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
  likelihood: likely
tags:
  - xss
  - cms
  - privilege-escalation
vendors:
  - Ghost Foundation
products:
  - Ghost CMS
cves:
  - id: CVE-2025-66849
    kev_status: unknown
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WOJTEKCHWALA-CVE-2025-66849
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WOJTEKCHWALA-CVE-2025-66849&utm_source=rss&utm_medium=rss
---

A public proof-of-concept (PoC) exploit has been published on Sploitus for CVE-2025-66849. According to the source, the vulnerability exists in the HTML block within the Ghost CMS post draft editor. An authenticated user with Contributor privileges can inject malicious JavaScript into a draft post. When an Owner account views or previews the post in the Ghost admin panel, the script executes with the Owner's privileges.
