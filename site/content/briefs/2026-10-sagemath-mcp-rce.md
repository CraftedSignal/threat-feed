---
brief_id: brief-2026-10-23-sagemath-mcp-rce
event_id: brief-2026-10-23-sagemath-mcp-rce
revision: 1
activity_at: "2026-10-23T15:42:47Z"
title: 'sagemath-mcp-server: Arbitrary code execution (CVE-2026-106763)'
slug: 2026-10-sagemath-mcp-rce
description: The sagemath-mcp-server package version 1.0.1 contains a vulnerability that allows a remote attacker to execute arbitrary code via the escapeShellString and sanitizeCode functions.
date: "2026-10-23T15:42:47Z"
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
  - cpe:2.3:a:justice8096:sagemath_mcp_server:*:*:*:*:*:*:*:*
vendors:
  - justice8096
products:
  - sagemath-mcp-server (1.0.1)
cves:
  - id: CVE-2026-106763
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106763
---

CVE-2026-106763 affects the @justice8096/sagemath-mcp-server package version 1.0.1. A remote attacker can execute arbitrary code via the escapeShellString and sanitizeCode functions.
