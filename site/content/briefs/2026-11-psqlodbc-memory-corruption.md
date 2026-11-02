---
brief_id: brief-2026-11-02-psqlodbc-memory-corruption
event_id: brief-2026-11-02-psqlodbc-memory-corruption
revision: 2
activity_at: "2026-11-02T21:52:50Z"
revision_history:
  - revision: 2
    at: "2026-11-02T21:52:50Z"
    checksum: sha256:2f0d38cab0442c004a65d1b58cef46a79a4c3c7f647120029bc16df5086cb1b7
    summary: added CVE-2026-120065
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120065
title: 'PostgreSQL: psqlODBC memory corruption via large-object read (CVE-2026-120057)'
slug: 2026-11-psqlodbc-memory-corruption
description: The psqlODBC driver is vulnerable to memory corruption during loread operations because it fails to validate server-provided data lengths against buffer sizes.
date: "2026-11-02T19:49:40Z"
lastmod: "2026-11-02T21:51:56Z"
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
  - psqlODBC (< 18.00.0006)
cves:
  - id: CVE-2026-120057
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-120065
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120057
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120065
updates:
  - at: "2026-11-02T21:51:56Z"
    level: L2
    summary: added CVE-2026-120065
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120065
---

A memory corruption vulnerability exists in the psqlODBC driver. During large-object read (loread) operations, the driver copies data into the application's buffer using the length provided by the server without comparing it to the actual buffer size. An untrusted server or a man-in-the-middle can provide an excessive length, causing the driver to return more bytes than the buffer can hold, resulting in an overwrite of adjacent memory in the client process. Fetching any large-object column can trigger this condition.
