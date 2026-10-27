---
brief_id: brief-2026-10-27-hitachi-jp1-overflow
event_id: brief-2026-10-27-hitachi-jp1-overflow
revision: 1
activity_at: "2026-10-27T10:58:13Z"
title: 'Hitachi JP1: Heap-based buffer overflow (CVE-2026-86576)'
slug: 2026-10-hitachi-jp1-overflow
description: A heap-based buffer overflow vulnerability has been identified in multiple Hitachi JP1 products.
date: "2026-10-27T10:58:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - JP1/Integrated Management 3 - Manager (13-00 before 13-50-31)
  - JP1/Automatic Job Management System 3 - Manager (13-00 before 13-50-31)
  - JP1/Automatic Job Management System 3 - Agent (13-00 before 13-50-31)
  - JP1/Automatic Job Management System 3 - Agent Minimal Edition (13-00 before 13-50-31)
  - JP1/Base (11-00 before 12-50-54)
cves:
  - id: CVE-2026-86576
    cvss: 9.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86576
---

CVE-2026-86576 is a heap-based buffer overflow vulnerability affecting specific versions of Hitachi JP1/Integrated Management 3 - Manager, JP1/Automatic Job Management System 3 (Manager, Agent, and Agent Minimal Edition), and JP1/Base. The vulnerability has a CVSS v3.1 base score of 9.4.
