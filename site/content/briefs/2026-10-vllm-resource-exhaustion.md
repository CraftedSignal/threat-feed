---
brief_id: brief-2026-10-25-vllm-resource-exhaustion
event_id: brief-2026-10-25-vllm-resource-exhaustion
revision: 1
activity_at: "2026-10-25T14:32:24Z"
title: 'vLLM: Uncontrolled resource consumption via image processing (CVE-2026-116177)'
slug: 2026-10-vllm-resource-exhaustion
description: An unauthenticated denial of service vulnerability in vLLM versions 0.10.2 through 0.24.x allows attackers to trigger an out-of-memory condition by submitting decompression-bomb images to the /v1/chat/completions endpoint.
date: "2026-10-25T14:32:24Z"
lastmod: "2026-10-25T14:32:32Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; no IOCs or specific Sigma logic available in text
cpes:
  - cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - webserver
vendors:
  - vLLM
products:
  - vLLM (0.10.2 <= version < 0.25.0)
  - vLLM (0.8.5 <= version < 0.31.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can submit a pathological decompression-bomb image to /v1/chat/completions to OOM-kill the worker and deny service to co-tenants.
    confidence_band: high
cves:
  - id: CVE-2026-116177
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-116180
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116177
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116180
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade vLLM to 0.25.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-116177 remediation
    - action: Upgrade vLLM to version 0.31.0 or later
      owner: IT Operations
      due: 24h
      evidence: vLLM from 0.8.5 before 0.31.0 has a denial of service flaw.
  hunt_leads:
    - lead: Identify abnormal memory usage spikes or frequent process restarts of vLLM worker containers
      technique_id: T1499
      data_needed:
        - Container metrics (memory usage)
        - Orchestrator logs (OOMKill events)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability leads to OOM-killing of worker processes
    - lead: Search application logs for repeated OverflowError exceptions associated with tokenizer decode functions.
      technique_id: T1499
      data_needed:
        - Application logs (stderr/stdout from vLLM engine)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: A client sharing the engine can send prompt_logprobs (or echo with logprobs) against a connector-cached prefix, making tokenizer decode raise OverflowError.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vLLM to 0.25.0
      owner: IT Operations
      addresses: CVE-2026-116177
      evidence: NVD advisory
    - priority: immediate
      action: Upgrade to vLLM 0.31.0
      owner: IT Operations
      addresses: CVE-2026-116180
      evidence: vLLM from 0.8.5 before 0.31.0 has a denial of service flaw.
updates:
  - at: "2026-10-25T14:32:32Z"
    level: L2
    summary: added coverage for vLLM (0.8.5 <= version < 0.31.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116180
---

vLLM versions 0.10.2 through 0.24.x are vulnerable to uncontrolled resource consumption (CVE-2026-116177). The vulnerability originates in the Nemotron-VL processor configuration, which sets the Pillow library attribute Image.MAX_IMAGE_PIXELS to None. This removes the default safety limit for image processing, allowing an unauthenticated attacker to supply a large, malicious image file to the /v1/chat/completions API endpoint, leading to process memory exhaustion and service denial.

## Impact

Successful exploitation results in an OOM (out-of-memory) kill of the vLLM worker process, causing a denial of service for all users of the affected worker instance.

## Recommendation

- Upgrade vLLM to version 0.25.0 or later immediately to restore image pixel limits.
- Audit network access to the /v1/chat/completions endpoint to restrict exposure to trusted clients where possible.
- Configure resource limits (cgroups or container-level memory limits) for vLLM workers to mitigate the impact of OOM events.
