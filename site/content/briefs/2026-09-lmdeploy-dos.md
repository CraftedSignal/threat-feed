---
title: Denial of Service Vulnerability in InternLM LMDeploy
slug: 2026-09-lmdeploy-dos
description: InternLM LMDeploy version 0.17.0 and earlier is vulnerable to a denial-of-service attack due to improper session management in DistServe mode, allowing unauthenticated attackers to cause an out-of-memory failure on the prefill worker.
date: "2026-09-17T16:00:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:internlm:lmdeploy:*:*:*:*:*:*:*:*
vendors:
  - InternLM
products:
  - LMDeploy (<= 0.17.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Unauthenticated attackers can send completion requests to the proxy endpoint that accumulate unreleased scheduler metadata and memory until the prefill worker is out-of-memory killed.
    confidence_band: high
cves:
  - id: CVE-2026-92983
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92983
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to LMDeploy proxy endpoint via network segmentation
      owner: SOC
      due: 24h
      evidence: Unauthenticated attackers can send completion requests
  enrichment_needed:
    - item: Patched version number
      owner: CTI
      reason: Upgrade guidance requires a fixed version number
      evidence: NVD record is current
  mitigation_plan:
    - priority: immediate
      action: Implement rate limiting on the proxy endpoint
      owner: IT Operations
      addresses: CVE-2026-92983
      evidence: Accumulation of metadata leads to OOM
---

InternLM LMDeploy through version 0.17.0 contains a vulnerability within the DistServe prefill/decode disaggregation mode. The flaw originates from the proxy component's improper handling of scheduler sessions. Specifically, the proxy incorrectly utilizes user-facing session IDs instead of internal scheduler keys, preventing the system from properly releasing scheduler sessions upon request completion.

Unauthenticated attackers can exploit this behavior by flooding the proxy endpoint with specifically crafted completion requests. Because the system fails to clean up these sessions, they accumulate indefinitely, leading to a rapid consumption of scheduler metadata and system memory. This resource exhaustion eventually forces the prefill worker process into an out-of-memory (OOM) killed state, effectively causing a persistent denial of service. The vulnerability is critical for environments where LMDeploy is exposed to public or untrusted network segments, as it requires no authentication to initiate the exploit.

## Impact

Successful exploitation results in the unavailability of the affected LLM inference service. In a production environment using DistServe, the termination of the prefill worker halts the processing of all incoming inference requests. Organizations relying on LMDeploy for automated AI workloads will face service disruption, requiring a manual restart of the worker nodes and potential remediation of the underlying memory leak by upgrading or patching the LMDeploy configuration.

## Recommendation

Prioritize the identification of internet-facing LMDeploy instances and verify their version. Upgrade to a version of LMDeploy that resolves the session management flaw in DistServe mode. If an immediate upgrade is not feasible, restrict access to the LMDeploy proxy endpoint using network-layer controls, such as IP allowlisting or authentication proxies, to prevent unauthenticated access by external entities. Monitor resource utilization metrics on worker nodes for unexpected spikes in memory usage linked to the proxy service.
