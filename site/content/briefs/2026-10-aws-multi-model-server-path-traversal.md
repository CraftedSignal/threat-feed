---
brief_id: brief-2026-10-23-aws-multi-model-server-path-traversal
event_id: brief-2026-10-23-aws-multi-model-server-path-traversal
revision: 1
activity_at: "2026-10-23T19:51:00Z"
title: 'Amazon Web Services Multi Model Server: Relative path traversal (CVE-2026-115812)'
slug: 2026-10-aws-multi-model-server-path-traversal
description: Amazon Web Services Multi Model Server 1.1.11 and earlier is vulnerable to a relative path traversal attack during model archive extraction, which may allow remote actors to execute arbitrary code via a crafted model archive.
date: "2026-10-23T19:51:00Z"
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
cpes:
  - cpe:2.3:a:amazon:multi_model_server:*:*:*:*:*:*:*:*
vendors:
  - Amazon
products:
  - Multi Model Server (<= 1.1.11)
cves:
  - id: CVE-2026-115812
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115812
---

Amazon Web Services Multi Model Server (MMS) versions 1.1.11 and earlier contain a relative path traversal vulnerability. An attacker can exploit this during model archive extraction to potentially execute arbitrary code. Multi Model Server is end of life and no fixed version is available.

## Impact
The vulnerability has been assigned a CVSS v3.1 base score of 9.8.

## Recommendation
- Discontinue use of Multi Model Server.
- Migrate to a supported model serving solution.
