---
brief_id: brief-2026-10-26-syncplify-bypass
event_id: brief-2026-10-26-syncplify-bypass
revision: 1
activity_at: "2026-10-26T17:44:26Z"
title: 'Syncplify Server!: Access control bypass (CVE-2026-112343)'
slug: 2026-10-syncplify-bypass
description: Syncplify Server! before 8.8.0 contains an access control bypass vulnerability that allows authenticated SFTP users to evade per-path permission overrides.
date: "2026-10-26T17:44:26Z"
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
  - cpe:2.3:a:syncplify:server:*:*:*:*:*:*:*:*
vendors:
  - Syncplify
products:
  - Syncplify Server! (< 8.8.0)
cves:
  - id: CVE-2026-112343
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112343
---

Syncplify Server! before 8.8.0 contains an access control bypass vulnerability that allows authenticated SFTP users to evade per-path permission overrides by exploiting case-insensitive filesystem path resolution and 8.3 short names. Attackers can address a protected directory using alternate capitalization or its 8.3 short name to perform file uploads and downloads that the configured override is intended to deny, resulting in unauthorized file access.
