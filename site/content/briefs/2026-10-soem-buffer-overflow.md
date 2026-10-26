---
brief_id: brief-2026-10-26-soem-buffer-overflow
event_id: brief-2026-10-26-soem-buffer-overflow
revision: 1
activity_at: "2026-10-26T09:41:18Z"
title: 'SOEM: Multi-segment data transfer buffer overflow (CVE-2026-82944)'
slug: 2026-10-soem-buffer-overflow
description: SOEM version 2.0.0 and earlier is vulnerable to a memory buffer overflow during multi-segment data transfers due to a failure to track cumulative data size.
date: "2026-10-26T09:41:18Z"
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
  - SOEM (<= 2.0.0)
cves:
  - id: CVE-2026-82944
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82944
---

SOEM (Simple Open EtherCAT Master) versions 2.0.0 and earlier contain a vulnerability in the handling of multi-segment data transfers. The application performs a single validation check on the total data size at the beginning of a transfer but fails to track the cumulative size as individual segments arrive. This allows a malicious device to bypass initial size checks and write controlled data beyond allocated memory buffer boundaries, potentially enabling code execution.
