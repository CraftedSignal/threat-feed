---
title: Remote Denial of Service Vulnerability in SGLang Expert-Distribution Endpoint
slug: 2026-10-sg-lang-dos
description: A remote denial of service vulnerability in the SGLang library allows unauthenticated attackers to disrupt service via the Expert-Distribution Recording Endpoint (CVE-2026-112082).
date: "2026-10-19T06:58:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:sgl-project:sg-lang:*:*:*:*:*:*:*:*
vendors:
  - sgl-project
products:
  - SGLang (<= 0.5.19)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Such manipulation leads to denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-112082
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112082
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict network access to the SGLang Expert-Distribution Recording Endpoint.
      owner: IT Operations
      due: 24h
      evidence: The exploit is publicly available and might be used.
  enrichment_needed:
    - item: SGLang version update
      owner: CTI
      reason: Need to track the official release of the fix for CVE-2026-112082.
      evidence: The pull request to fix this issue awaits acceptance.
---

A vulnerability identified as CVE-2026-112082 affects the sgl-project SGLang library in versions up to and including 0.5.19. The flaw resides within the `Scheduler.expert_distribution_handle` function, located in `python/sglang/srt/eplb/expert_distribution.py`. This component, identified as the Expert-Distribution Recording Endpoint, is susceptible to remote manipulation. Successful exploitation of this vulnerability results in a denial of service (DoS) state, potentially causing service instability or total unavailability for applications utilizing the affected SGLang component. Public exploit code is currently available, increasing the risk of exploitation by malicious actors. Organizations using SGLang for structured generation or large language model serving should identify if this specific endpoint is exposed and monitor for abnormal traffic patterns targeting this function.

## Impact

Successful exploitation leads to a denial of service, rendering the affected SGLang endpoint unresponsive. This impacts organizations relying on SGLang for model inference or serving, potentially disrupting dependent AI/ML applications and services. The vulnerability is remotely exploitable, increasing the attack surface for internet-facing instances of SGLang.

## Recommendation

* Monitor for any unusual remote access to the Expert-Distribution Recording Endpoint until a patch is merged and deployed.
* Audit application deployments to determine if the vulnerable `python/sglang/srt/eplb/expert_distribution.py` component is active and accessible.
* Subscribe to sgl-project repository updates to identify when the pending pull request for CVE-2026-112082 is merged and released in a patched version.
* If the endpoint is not required for production operations, restrict access via firewall or load balancer rules.
