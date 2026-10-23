---
brief_id: brief-2026-10-23-mcp-docker-tools-rce
event_id: brief-2026-10-23-mcp-docker-tools-rce
revision: 1
activity_at: "2026-10-23T15:43:06Z"
title: 'mcp-docker-tools: Remote code execution in handleImageList (CVE-2026-106765)'
slug: 2026-10-mcp-docker-tools-rce
description: CVE-2026-106765 identifies that @rog0x/mcp-docker-tools version 1.0.1 allows a remote attacker to execute arbitrary code via the handleImageList function.
date: "2026-10-23T15:43:06Z"
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
  - '@rog0x/mcp-docker-tools (1.0.1)'
cves:
  - id: CVE-2026-106765
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106765
---

An issue in @rog0x/mcp-docker-tools 1.0.1 allows a remote attacker to execute arbitrary code via the handleImageList function. The CVSS v3.1 base score for this vulnerability is 7.5.
