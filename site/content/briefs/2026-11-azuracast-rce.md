---
brief_id: brief-2026-11-03-azuracast-rce
event_id: brief-2026-11-03-azuracast-rce
revision: 2
activity_at: "2026-11-03T16:15:50Z"
revision_history:
  - revision: 2
    at: "2026-11-03T16:15:50Z"
    checksum: sha256:7b06df400d2a78bf56e6796c0b29c4bda86ee3accebc4330ef3c1e0893190b63
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121428&utm_source=rss&utm_medium=rss
title: 'AzuraCast: Remote code execution via station timezone injection (CVE-2026-121428)'
slug: 2026-11-azuracast-rce
description: AzuraCast versions through 0.23.8 are vulnerable to remote code execution where an authenticated station manager can inject malicious Supervisor configuration via the timezone field.
date: "2026-11-03T16:00:00Z"
lastmod: "2026-11-03T16:14:48Z"
type: advisory
claim_state: <nil>
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-121428&utm_source=rss&utm_medium=rss
products:
  - AzuraCast (<= 0.23.8)
cves:
  - id: CVE-2026-121428
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121428
  - https://sploitus.com/exploit?id=CVE-2026-121428&utm_source=rss&utm_medium=rss
updates:
  - at: "2026-11-03T16:14:48Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-121428&utm_source=rss&utm_medium=rss
---

AzuraCast through 0.23.8 contains a remote code execution vulnerability that allows authenticated station managers to inject Supervisor configuration through the station timezone field. Attackers can submit a timezone containing newlines to the profile edit API, defining a new Supervisor program that executes OS commands as root when configuration regenerates.
