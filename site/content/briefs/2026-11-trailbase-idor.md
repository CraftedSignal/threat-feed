---
brief_id: brief-2026-11-10-trailbase-idor
event_id: brief-2026-11-10-trailbase-idor
revision: 1
activity_at: "2026-11-10T02:01:54Z"
title: 'TrailBase: Insecure direct object reference in std.FileUpload (CVE-2026-119759)'
slug: 2026-11-trailbase-idor
description: TrailBase 0.28.2 before 0.35.10 contains an insecure direct object reference (IDOR) vulnerability in std.FileUpload columns that lacks ownership validation.
date: "2026-11-10T02:01:54Z"
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
  - cpe:2.3:a:trailbase:trailbase:*:*:*:*:*:*:*:*
vendors:
  - TrailBase
products:
  - TrailBase (0.28.2 before 0.35.10)
cves:
  - id: CVE-2026-119759
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119759
---

TrailBase 0.28.2 before 0.35.10 contains an insecure direct object reference vulnerability that allows authenticated attackers to manipulate the object-store id metadata within std.FileUpload columns without ownership validation during insert and update operations. Attackers can reference another user's or table's file id in a record they own to read the victim's file bytes, trigger permanent deletion of the victim's file, or use a $like filter on the file column to brute-force recover stripped ids character by character.
