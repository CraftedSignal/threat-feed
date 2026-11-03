---
brief_id: brief-2026-11-03-azuracast-rce
event_id: brief-2026-11-03-azuracast-rce
revision: 1
activity_at: "2026-11-03T16:00:00Z"
title: 'AzuraCast: Remote code execution via station timezone injection (CVE-2026-121428)'
slug: 2026-11-azuracast-rce
description: AzuraCast versions through 0.23.8 are vulnerable to remote code execution where an authenticated station manager can inject malicious Supervisor configuration via the timezone field.
date: "2026-11-03T16:00:00Z"
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
products:
  - AzuraCast (<= 0.23.8)
cves:
  - id: CVE-2026-121428
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121428
---

AzuraCast through 0.23.8 contains a remote code execution vulnerability that allows authenticated station managers to inject Supervisor configuration through the station timezone field. Attackers can submit a timezone containing newlines to the profile edit API, defining a new Supervisor program that executes OS commands as root when configuration regenerates.
