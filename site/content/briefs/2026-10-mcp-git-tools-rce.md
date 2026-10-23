---
brief_id: brief-2026-10-23-mcp-git-tools-rce
event_id: brief-2026-10-23-mcp-git-tools-rce
revision: 1
activity_at: "2026-10-23T15:42:56Z"
title: 'mcp-git-tools: Remote code execution via resolveBaseBranch (CVE-2026-106764)'
slug: 2026-10-mcp-git-tools-rce
description: The @rog0x/mcp-git-tools package version 1.0.1 contains a vulnerability that allows a remote attacker to execute arbitrary code via the resolveBaseBranch function.
date: "2026-10-23T15:42:56Z"
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
  - '@rog0x/mcp-git-tools (1.0.1)'
cves:
  - id: CVE-2026-106764
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106764
---

CVE-2026-106764 is a vulnerability in @rog0x/mcp-git-tools version 1.0.1. The issue allows a remote attacker to execute arbitrary code via the resolveBaseBranch function.
