---
brief_id: brief-2026-10-28-ai-gateway-payload-processing-auth-bypass
event_id: brief-2026-10-28-ai-gateway-payload-processing-auth-bypass
revision: 1
activity_at: "2026-10-28T20:37:55Z"
title: 'ai-gateway-payload-processing: Unauthorized resource access via model identifier (CVE-2026-117574)'
slug: 2026-10-ai-gateway-payload-processing-auth-bypass
description: An authenticated remote attacker can exploit a flaw in ai-gateway-payload-processing by submitting a request specifying another tenant's model identifier, resulting in unauthorized LLM resource consumption.
date: "2026-10-28T20:37:55Z"
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
  - ai-gateway-payload-processing
cves:
  - id: CVE-2026-117574
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117574
---

A flaw was found in ai-gateway-payload-processing. An authenticated remote attacker can exploit this vulnerability by submitting a request specifying another tenant's model identifier in the request body or header. The service does not verify authorization before retrieving credentials from the shared store, causing it to inject the target tenant's application programming interface (API) keys into the request. This allows an attacker to perform unauthorized requests and consume another tenant's large language model (LLM) resources and quotas.
