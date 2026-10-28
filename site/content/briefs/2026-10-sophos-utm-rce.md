---
brief_id: brief-2026-10-28-sophos-utm-rce
event_id: brief-2026-10-28-sophos-utm-rce
revision: 1
activity_at: "2026-10-28T23:37:00Z"
title: 'Sophos UTM: Unauthenticated Remote Code Execution (CVE-2026-118633)'
slug: 2026-10-sophos-utm-rce
description: A path traversal and race condition vulnerability exists in the Sophos UTM email proxy, allowing unauthenticated remote attackers to execute arbitrary code as root.
date: "2026-10-28T23:37:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:sophos:utm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - sophos
vendors:
  - Sophos
products:
  - Sophos UTM
cves:
  - id: CVE-2026-118633
    cvss: 8.1
    kev_status: "false"
references:
  - https://www.sophos.com/en-us/security-advisories/sophos-sa-20261028-utm-rce
  - https://sploitus.com/exploit?id=CVE-2026-118633
  - https://sploitus.com/exploit?id=CVE-2026-118633&utm_source=rss&utm_medium=rss
---

A path traversal vulnerability combined with a race condition in the Sophos UTM email proxy allows a remote unauthenticated attacker to execute arbitrary code as root. Successful exploitation requires sustaining repeated attacks for several minutes while the email proxy is used with scanning enabled. Sophos UTM is end-of-life, and patches must be applied manually. A Proof of Concept (PoC) exploit has been published on Sploitus.
