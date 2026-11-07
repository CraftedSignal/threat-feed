---
brief_id: brief-2026-11-07-openbmb-internet-of-agents-injection
event_id: brief-2026-11-07-openbmb-internet-of-agents-injection
revision: 1
activity_at: "2026-11-07T01:38:04Z"
title: 'OpenBMB Internet of Agents: Improper neutralization in Agent Registry (CVE-2026-123791)'
slug: 2026-11-openbmb-internet-of-agents-injection
description: A vulnerability in the Agent Registry component of OpenBMB Internet of Agents allows remote attackers to manipulate data query logic via the key argument in the _primary_field_query function.
date: "2026-11-07T01:38:04Z"
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
  - cpe:2.3:a:openbmb:internet_of_agents:*:*:*:*:*:*:*:*
vendors:
  - OpenBMB
products:
  - Internet of Agents (up to commit 9d78e88e47160eb42ee1ee8538c05e1c2c47877a)
cves:
  - id: CVE-2026-123791
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123791
---

A vulnerability exists in the Agent Registry component of OpenBMB Internet of Agents (up to commit 9d78e88e47160eb42ee1ee8538c05e1c2c47877a). The vulnerability resides in the _primary_field_query function of common/utils/milvus_utils.py. Manipulation of the key argument results in improper neutralization of special elements in data query logic. The attack may be launched remotely, and the exploit is public. The project has not yet responded to an issue report regarding this vulnerability.
