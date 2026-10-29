---
brief_id: brief-2026-10-25-vllm-resource-exhaustion
event_id: brief-2026-10-25-vllm-resource-exhaustion
revision: 4
activity_at: "2026-10-29T20:03:29Z"
revision_history:
  - revision: 2
    at: "2026-10-25T16:08:31Z"
    checksum: sha256:64e9431bea6b0f03bcba0cef387c4a77507976e827e334c51cb78fb56eeb448d
    summary: added CVE-2026-114055
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-gx7p-2j49-hfq4
  - revision: 3
    at: "2026-10-29T19:50:13Z"
    checksum: sha256:9a40b79eb1510dc9ffe7ef856da1dd828b7a21c30553f7a22773e392dff43704
    summary: added coverage for vLLM
    changed_fields:
      - action_plan
      - affected_products
      - cves
      - lastmod
      - priority_signals
      - references
      - severity
      - tags
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4195
  - revision: 4
    at: "2026-10-29T20:03:29Z"
    checksum: sha256:3a6bf49a1035504ad3f2b16d2459895087f07873b05797ff1a74660fc20a04dc
    summary: vllm version 0.18.0 <= x < 0.31.0
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116179
title: 'vLLM: Uncontrolled resource consumption via image processing (CVE-2026-116177)'
slug: 2026-10-vllm-resource-exhaustion
description: An unauthenticated denial of service vulnerability in vLLM versions 0.10.2 through 0.24.x allows attackers to trigger an out-of-memory condition by submitting decompression-bomb images to the /v1/chat/completions endpoint.
date: "2026-10-25T14:32:24Z"
lastmod: "2026-10-29T20:01:45Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - medium
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
  - info-disclosure
vendors:
  - vLLM
products:
  - vLLM (0.10.2 <= version < 0.25.0)
  - vLLM (0.8.5 <= version < 0.31.0)
  - vllm (>= 0.7.3, < 0.31.0)
  - vLLM
  - vLLM (0.18.0 <= x < 0.31.0)
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
    epss: 0.00291
    kev_status: "false"
  - id: CVE-2026-116180
    cvss: 7.7
    epss: 0.00249
    kev_status: "false"
  - id: CVE-2026-114055
    cvss: 7.5
    epss: 0.0042
    kev_status: "false"
  - id: CVE-2026-116179
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116177
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116180
  - https://github.com/advisories/GHSA-gx7p-2j49-hfq4
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4151
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4195
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116179
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
    - Security Engineering
  immediate_actions:
    - action: Upgrade vLLM to 0.25.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-116177 remediation
    - action: Upgrade vLLM to version 0.31.0 or later
      owner: IT Operations
      due: 24h
      evidence: vLLM from 0.8.5 before 0.31.0 has a denial of service flaw.
    - action: Inventory all deployments of the vLLM library
      owner: IT Operations
      due: 48h
      evidence: Source advisory indicates multiple vulnerabilities requiring remediation
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
    - priority: immediate
      action: Monitor official vLLM repository for security updates and patches
      owner: Security Engineering
      addresses: Multiple undisclosed vulnerabilities in vLLM
      evidence: Source advisory indicates that patches are expected
  gaps:
    - Missing specific CVE identifiers and patch versions in the current advisory
updates:
  - at: "2026-10-25T14:32:32Z"
    level: L2
    summary: added coverage for vLLM (0.8.5 <= version < 0.31.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116180
  - at: "2026-10-25T16:07:32Z"
    level: L2
    summary: added CVE-2026-114055
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gx7p-2j49-hfq4
  - at: "2026-10-29T19:48:38Z"
    level: L2
    summary: added coverage for vLLM
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4195
  - at: "2026-10-29T20:01:45Z"
    level: L2
    summary: vllm version 0.18.0 <= x < 0.31.0
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116179
---

vLLM versions 0.10.2 through 0.24.x are vulnerable to uncontrolled resource consumption (CVE-2026-116177). The vulnerability originates in the Nemotron-VL processor configuration, which sets the Pillow library attribute Image.MAX_IMAGE_PIXELS to None. This removes the default safety limit for image processing, allowing an unauthenticated attacker to supply a large, malicious image file to the /v1/chat/completions API endpoint, leading to process memory exhaustion and service denial.

## Impact

Successful exploitation results in an OOM (out-of-memory) kill of the vLLM worker process, causing a denial of service for all users of the affected worker instance.

## Recommendation

- Upgrade vLLM to version 0.25.0 or later immediately to restore image pixel limits.
- Audit network access to the /v1/chat/completions endpoint to restrict exposure to trusted clients where possible.
- Configure resource limits (cgroups or container-level memory limits) for vLLM workers to mitigate the impact of OOM events.
