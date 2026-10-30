---
brief_id: brief-2026-10-30-lmdeploy-rce
event_id: brief-2026-10-30-lmdeploy-rce
revision: 1
activity_at: "2026-10-30T17:36:00Z"
title: 'InternLM LMDeploy: Unauthenticated remote code execution (CVE-2026-119706)'
slug: 2026-10-lmdeploy-rce
description: InternLM LMDeploy versions 0.9.0 through 0.18.0 are vulnerable to unauthenticated remote code execution via insecure deserialization of pickled data.
date: "2026-10-30T17:36:00Z"
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
  - cpe:2.3:a:internlm:lmdeploy:*:*:*:*:*:*:*:*
vendors:
  - InternLM
products:
  - LMDeploy (0.9.0 through 0.18.0)
cves:
  - id: CVE-2026-119706
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119706
---

InternLM LMDeploy versions 0.9.0 through 0.18.0 contain an unauthenticated remote code execution vulnerability. Remote attackers can execute OS commands by sending a base64-encoded crafted pickle to the '/update_weights' endpoint within the 'serialized_named_tensors' parameter. The application's use of 'ForkingPickler.loads' to deserialize this input without validation allows for command execution as the api_server process.
