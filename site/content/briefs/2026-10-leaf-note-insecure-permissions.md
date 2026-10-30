---
brief_id: brief-2026-10-30-leaf-note-insecure-permissions
event_id: brief-2026-10-30-leaf-note-insecure-permissions
revision: 1
activity_at: "2026-10-30T21:43:41Z"
title: 'Leaf Note: Insecure permissions arbitrary data access (CVE-2026-107034)'
slug: 2026-10-leaf-note-insecure-permissions
description: LeafPad / Leaf Note v1.21 (versionCode 21) contains an insecure permissions vulnerability that allows unauthorized attackers to arbitrarily read another user's note data.
date: "2026-10-30T21:43:41Z"
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
cpes:
  - cpe:2.3:a:leafpad:leaf_note:*:*:*:*:*:*:*:*
vendors:
  - LeafPad
products:
  - Leaf Note (v1.21, versionCode 21)
cves:
  - id: CVE-2026-107034
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107034
---

LeafPad / Leaf Note version 1.21 (versionCode 21) is affected by an insecure permissions vulnerability. This flaw allows unauthorized attackers to arbitrarily read another user's note data. The vulnerability is assigned CVE-2026-107034 and a CVSS v3.1 base score of 9.1.
