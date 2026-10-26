---
brief_id: brief-2026-10-26-vllm-insecure-deserialization
event_id: brief-2026-10-26-vllm-insecure-deserialization
revision: 1
activity_at: "2026-10-26T17:45:55Z"
title: 'vLLM: Insecure deserialization via multimodal shared memory (CVE-2026-115912)'
slug: 2026-10-vllm-insecure-deserialization
description: An authenticated caller can place forged shared-memory address and monotonic_id values in public multimodal features.kwargs_data, allowing arbitrary Python execution on vLLM worker nodes via pickle.loads().
date: "2026-10-26T17:45:55Z"
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
  - vLLM (< 0.32.0)
cves:
  - id: CVE-2026-115912
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115912
---

In vLLM versions prior to 0.32.0, an authenticated caller can place forged shared-memory address and monotonic_id values in public multimodal features.kwargs_data. In scale-out deployments with shared-memory multimodal caching enabled, workers trust these values and pass attacker-selected bytes to pickle.loads(), allowing arbitrary Python execution even when insecure serialization is disabled.
