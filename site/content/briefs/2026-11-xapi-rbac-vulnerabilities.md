---
brief_id: brief-2026-11-11-xapi-rbac-vulnerabilities
event_id: brief-2026-11-11-xapi-rbac-vulnerabilities
revision: 1
activity_at: "2026-11-11T01:38:19Z"
title: 'Xen Project: XAPI multiple role-based access control vulnerabilities'
slug: 2026-11-xapi-rbac-vulnerabilities
description: The Xen Project has released XSA-530 v2, which describes multiple issues regarding Role-Based Access Control (RBAC) in XAPI.
date: "2026-11-11T01:38:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
cves:
  - id: CVE-2026-102706
    kev_status: unknown
  - id: CVE-2026-102707
    kev_status: unknown
  - id: CVE-2026-102708
    kev_status: unknown
  - id: CVE-2026-119779
    kev_status: unknown
  - id: CVE-2026-119780
    kev_status: unknown
references:
  - https://xenbits.xen.org/xsa/advisory-530.html
  - https://seclists.org/oss-sec/2026/q4/642
---

The Xen Project has released XSA-530 v2, addressing multiple RBAC issues in the XAPI toolstack. XAPI allows users to be configured with different roles using Role-Based Access Control.
