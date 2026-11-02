---
brief_id: brief-2026-11-02-psqlodbc-memory-corruption
event_id: brief-2026-11-02-psqlodbc-memory-corruption
revision: 1
activity_at: "2026-11-02T19:49:40Z"
title: 'PostgreSQL: psqlODBC memory corruption via large-object read (CVE-2026-120057)'
slug: 2026-11-psqlodbc-memory-corruption
description: The psqlODBC driver is vulnerable to memory corruption during loread operations because it fails to validate server-provided data lengths against buffer sizes.
date: "2026-11-02T19:49:40Z"
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
tags:
  - vulnerability
  - memory-corruption
  - psqlodbc
  - postgresql
products:
  - psqlODBC (versions before 18.00.0006)
cves:
  - id: CVE-2026-120057
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120057
---

A memory corruption vulnerability exists in the psqlODBC driver. During large-object read (loread) operations, the driver copies data into the application's buffer using the length provided by the server without comparing it to the actual buffer size. An untrusted server or a man-in-the-middle can provide an excessive length, causing the driver to return more bytes than the buffer can hold, resulting in an overwrite of adjacent memory in the client process. Fetching any large-object column can trigger this condition.
