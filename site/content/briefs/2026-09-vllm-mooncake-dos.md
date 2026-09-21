---
title: Denial of Service in vLLM Mooncake Connector via KV Cache Exhaustion
slug: 2026-09-vllm-mooncake-dos
description: The vLLM Mooncake connector up to version 0.29.0 is susceptible to a denial-of-service attack where malicious completion requests exhaust GPU memory by orphaned KV cache blocks.
date: "2026-09-21T22:31:23Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:vllm:mooncake_connector:*:*:*:*:*:*:*:*
vendors:
  - vLLM
products:
  - Mooncake connector (<= 0.29.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can trigger GPU memory exhaustion by submitting completion requests with multiple prompts, causing orphaned KV cache blocks to accumulate until process restart.
    confidence_band: high
cves:
  - id: CVE-2026-94627
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94627
action_plan:
  priority: elevated
  owners:
    - DevOps
    - SRE
  immediate_actions:
    - action: Upgrade vLLM Mooncake connector to version 0.30.0 or later
      owner: DevOps
      due: 72h
      evidence: CVE-2026-94627 remediation
  mitigation_plan:
    - priority: immediate
      action: Implement request rate limiting for completion API endpoints
      owner: DevOps
      addresses: CVE-2026-94627
      evidence: CVE-2026-94627
---

The vLLM Mooncake connector, used in disaggregated prefill/decode deployments, contains a vulnerability in the management of GPU Key-Value (KV) cache block ownership. When concurrent child requests share a single transfer ID, the connector fails to properly reconcile ownership, leading to the accumulation of orphaned memory blocks. An attacker can deliberately trigger this condition by submitting completion requests containing multiple prompts, forcing the system to allocate memory that is never subsequently freed. This persistent memory leak eventually results in GPU memory exhaustion, preventing the processing of legitimate requests and causing a service-wide denial of service until the affected process is restarted. This vulnerability is identified as CVE-2026-94627.

## Impact

Successful exploitation results in a denial of service for the vLLM instance. This impacts organizations relying on vLLM for high-throughput LLM serving, particularly those using disaggregated deployment architectures. Memory exhaustion renders the service unable to process legitimate requests, leading to potential operational outages in production machine learning environments.

## Recommendation

Prioritized actions for engineering and security teams:
- Upgrade the vLLM Mooncake connector to a version beyond 0.29.0 to patch CVE-2026-94627.
- Implement request rate limiting and input validation at the API gateway layer to prevent the submission of excessively complex or concurrent prompts designed to trigger this memory exhaustion.
- Monitor GPU memory usage metrics for abnormal, linear growth patterns that do not correlate with legitimate traffic volume.
