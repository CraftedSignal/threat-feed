---
brief_id: brief-2026-10-22-json-scada-sql-injection
event_id: brief-2026-10-22-json-scada-sql-injection
revision: 1
activity_at: "2026-10-22T14:17:09Z"
title: 'JSON-SCADA: SQL injection vulnerability (CVE-2026-115328)'
slug: 2026-10-json-scada-sql-injection
description: JSON-SCADA before 0.65-alpha contains an SQL injection vulnerability in the opcApi() function within src/server_realtime_auth/index.js.
date: "2026-10-22T14:17:09Z"
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
  - JSON-SCADA (< 0.65-alpha)
cves:
  - id: CVE-2026-115328
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115328
---

JSON-SCADA before 0.65-alpha contains an SQL injection vulnerability in the opcApi() function in src/server_realtime_auth/index.js. Authenticated users can inject SQL via HistoryReadRequest parameters (NodeId.Id, StartTime, or EndTime), allowing for stacked statements that can read, modify, or delete historian data regardless of role.
