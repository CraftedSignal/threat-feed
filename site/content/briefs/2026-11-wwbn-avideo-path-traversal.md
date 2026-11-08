---
brief_id: brief-2026-11-08-wwbn-avideo-path-traversal
event_id: brief-2026-11-08-wwbn-avideo-path-traversal
revision: 1
activity_at: "2026-11-08T15:29:37Z"
title: 'WWBN AVideo: Path traversal in receiveAsync.json.php (CVE-2026-124424)'
slug: 2026-11-wwbn-avideo-path-traversal
description: WWBN AVideo contains a path traversal vulnerability in plugin/AI/receiveAsync.json.php that allows holders of any valid AI token to write arbitrary .vtt files.
date: "2026-11-08T15:29:37Z"
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
  - cpe:2.3:a:wwbn:avideo:*:*:*:*:*:*:*:*
vendors:
  - WWBN
products:
  - AVideo
cves:
  - id: CVE-2026-124424
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124424
---

WWBN AVideo contains a path traversal vulnerability in plugin/AI/receiveAsync.json.php. Attackers with a valid AI token can inject traversal sequences into the unsanitized response[lang] parameter during a type=translation request. This allows for the planting of attacker-controlled content in the webroot or the overwriting of other users' subtitle files.
