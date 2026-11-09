---
brief_id: brief-2026-11-09-easy-js-wpapi-vuln
event_id: brief-2026-11-09-easy-js-wpapi-vuln
revision: 1
activity_at: "2026-11-09T17:49:49Z"
title: 'EASY-JS-WPAPI Client HANDLE: Sensitive information disclosure and authentication bypass (CVE-2026-115213)'
slug: 2026-11-easy-js-wpapi-vuln
description: The EASY-JS-WPAPI Client HANDLE WordPress plugin through version 2.0 does not prevent disclosure of stored administrator credentials to unauthenticated users and fails to correctly verify authentication, allowing unauthenticated attackers to gain full administrator access.
date: "2026-11-09T17:49:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - EASY-JS-WPAPI Client HANDLE for the WordPress REST-API (through 2.0)
cves:
  - id: CVE-2026-115213
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115213
---

CVE-2026-115213 identifies a vulnerability in the EASY-JS-WPAPI Client HANDLE for the WordPress REST-API plugin through version 2.0. The plugin fails to prevent disclosure of stored administrator credentials to unauthenticated users and does not correctly verify authentication, allowing unauthenticated attackers to obtain administrator credentials and gain full administrator access to the site.
