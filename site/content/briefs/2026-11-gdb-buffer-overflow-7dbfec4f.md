---
brief_id: brief-2026-11-05-gdb-buffer-overflow-7dbfec4f
event_id: brief-2026-11-05-gdb-buffer-overflow-7dbfec4f
revision: 1
activity_at: "2026-11-05T20:29:16Z"
title: 'GNU GDB: Stack buffer overflow in tracepoint upload handler (CVE-2026-121995)'
slug: 2026-11-gdb-buffer-overflow-7dbfec4f
description: A stack buffer overflow in the GDB client's tracepoint upload handler allows an attacker-controlled debug stub to corrupt stack memory during connection setup.
date: "2026-11-05T20:29:16Z"
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
  - cpe:2.3:a:gnu:gdb:*:*:*:*:*:*:*:*
vendors:
  - GNU
products:
  - GDB
cves:
  - id: CVE-2026-121995
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121995
---

CVE-2026-121995 is a stack buffer overflow vulnerability in the GDB client's tracepoint upload handler. During connection setup, an attacker-controlled debug stub can trigger the overflow by causing GDB to read beyond the current reply boundary into a stale prior reply in the shared packet buffer, resulting in corruption of stack memory.
