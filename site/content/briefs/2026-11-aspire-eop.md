---
brief_id: brief-2026-11-11-aspire-eop
event_id: brief-2026-11-11-aspire-eop
revision: 1
activity_at: "2026-11-11T01:54:27Z"
title: 'Microsoft .NET Aspire: Elevation of Privilege via Insecure Temporary File Permissions (CVE-2026-120778)'
slug: 2026-11-aspire-eop
description: An elevation of privilege vulnerability in .NET Aspire CLI (CVE-2026-120778) exists due to the creation of temporary files in directories with insecure permissions. This advisory is a duplicate of GHSA-m63f-xhvm-6mv5.
date: "2026-11-11T01:54:27Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:microsoft:aspire_cli:*:*:*:*:*:*:*:*
vendors:
  - Microsoft
products:
  - Aspire.Cli (>= 13.2.0, < 13.6.5)
cves:
  - id: CVE-2026-120778
    cvss: 7.3
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-hfpm-4fc4-g2wc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120778
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-120778
---

The .NET Aspire CLI (affected versions: >= 13.2.0, < 13.6.5) creates temporary files in directories with insecure permissions, which allows a local attacker to elevate privileges. This advisory has been withdrawn as a duplicate of GHSA-m63f-xhvm-6mv5.
