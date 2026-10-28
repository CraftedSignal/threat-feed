---
brief_id: brief-2026-10-28-xerte-rce
event_id: brief-2026-10-28-xerte-rce
revision: 1
activity_at: "2026-10-28T08:26:29Z"
title: 'Xerte Online Toolkits: Authenticated remote code execution (CVE-2026-117607)'
slug: 2026-10-xerte-rce
description: Xerte Online Toolkits through 3.15.5 contains a remote code execution vulnerability that allows authenticated users with system permission to run PHP by importing a crafted language pack.
date: "2026-10-28T08:26:29Z"
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
  - cpe:2.3:a:xerte:online_toolkits:*:*:*:*:*:*:*:*
vendors:
  - Xerte
products:
  - Xerte Online Toolkits (through 3.15.5)
cves:
  - id: CVE-2026-117607
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117607
---

Xerte Online Toolkits through 3.15.5 contains a remote code execution vulnerability. Authenticated users with system permissions can run PHP code by importing a crafted language pack. Attackers can upload a ZIP file via `import_language.php` containing a `.inc` file and request it through the `language` parameter to execute code on the server.
