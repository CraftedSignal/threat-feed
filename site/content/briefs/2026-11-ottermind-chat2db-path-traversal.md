---
brief_id: brief-2026-11-09-ottermind-chat2db-path-traversal
event_id: brief-2026-11-09-ottermind-chat2db-path-traversal
revision: 1
activity_at: "2026-11-09T07:31:45Z"
title: 'OtterMind Chat2DB: Path traversal vulnerability (CVE-2026-124557)'
slug: 2026-11-ottermind-chat2db-path-traversal
description: A path traversal vulnerability exists in the DbMybatisGenerateServiceImpl.generateClass function of OtterMind Chat2DB up to version 5.3.8.
date: "2026-11-09T07:31:45Z"
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
  - Chat2DB (up to 5.3.8)
cves:
  - id: CVE-2026-124557
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124557
---

A vulnerability was detected in OtterMind Chat2DB up to 5.3.8. The function `DbMybatisGenerateServiceImpl.generateClass` in `DbMybatisGenerateServiceImpl.java` (Class Generator component) is impacted. Manipulation of the `tableName` argument results in path traversal. The attack may be performed from remote. The exploit is public and the vendor did not respond to disclosure.
