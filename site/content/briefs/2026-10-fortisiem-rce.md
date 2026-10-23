---
brief_id: brief-2026-10-23-fortisiem-rce
event_id: brief-2026-10-23-fortisiem-rce
revision: 1
activity_at: "2026-10-23T17:43:48Z"
title: 'Fortinet FortiSIEM: Unauthenticated remote code execution (CVE-2026-106173)'
slug: 2026-10-fortisiem-rce
description: A public proof-of-concept exploit is available for CVE-2026-106173, an unauthenticated remote code execution vulnerability in Fortinet FortiSIEM.
date: "2026-10-23T17:43:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:fortinet:fortisiem:*:*:*:*:*:*:*:*
vendors:
  - Fortinet
products:
  - FortiSIEM
cves:
  - id: CVE-2026-106173
    cvss: 9.8
    epss: 0.00459
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=169A54EE-0D7E-5990-A956-2520F778FA10
  - https://horizon3.ai/attack-research/cve-2026-106173-deep-dive-fortisiem-grpc-path-traversal-file-write-rce/
  - https://sploitus.com/exploit?id=169A54EE-0D7E-5990-A956-2520F778FA10&utm_source=rss&utm_medium=rss
---

CVE-2026-106173 is an unauthenticated remote code execution vulnerability in Fortinet FortiSIEM. The vulnerability exists in the gRPC `QueryResultReq` handler, which processes untrusted metadata without proper path validation. Attackers can leverage path traversal sequences and NUL-byte injection to write arbitrary files to the filesystem. Publicly available exploit code targets the default gRPC port 27918.
