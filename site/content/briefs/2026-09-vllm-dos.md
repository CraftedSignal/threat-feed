---
title: vLLM Denial of Service via Unbounded Memory Allocation
slug: 2026-09-vllm-dos
description: An input validation flaw in vLLM version 0.29.0 and earlier allows remote attackers to cause a denial-of-service by submitting malicious parameters to OpenAI-compatible completion endpoints, triggering memory exhaustion.
date: "2026-09-21T22:31:17Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - input-validation
  - ai-security
vendors:
  - vLLM Project
products:
  - vLLM (<= 0.29.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can supply arbitrary tp_size values in prefill/decode disaggregated deployments to exhaust memory and trigger kernel OOM-kill of the decode worker process.
    confidence_band: high
cves:
  - id: CVE-2026-94626
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94626
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade vLLM to version > 0.29.0.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-94626 remediation requirement.
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to block or inspect JSON payloads containing tp_size parameters exceeding expected cluster configurations.
      owner: Security Operations
      addresses: CVE-2026-94626
      evidence: Source document indicates improper input validation of tp_size.
---

vLLM versions 0.29.0 and earlier are vulnerable to a denial-of-service condition due to improper input validation in the kv_transfer_params parameter handling for OpenAI-compatible completion endpoints. Specifically, the tp_size parameter does not enforce bounds during the initialization of disaggregated deployment configurations. By submitting an arbitrary, excessively large integer value for tp_size to the relevant API endpoints, an unauthenticated attacker can force the system to perform unbounded memory allocation. This exhaustion of host system resources eventually leads the operating system kernel to invoke the Out-Of-Memory (OOM) killer, which terminates the affected decode worker process. This vulnerability significantly impacts the availability of inference services deployed using the disaggregated architecture.

## Impact

Successful exploitation results in the immediate termination of the vLLM decode worker process, rendering the inference service unavailable for the affected deployment. This denial-of-service affects organizations relying on vLLM for high-throughput or disaggregated AI model serving. Given the ease of sending malicious API requests, infrastructure stability is at high risk until the service is patched or the input is restricted.

## Recommendation

Prioritize the upgrade of all vLLM deployments to a patched version beyond 0.29.0 to address CVE-2026-94626. In environments where immediate patching is not feasible, implement strict input validation at the API gateway or reverse proxy level to reject requests containing unexpectedly large or non-standard tp_size integers within the kv_transfer_params JSON object. Monitor system logs for repeated OOM-killer events involving the vLLM decode worker process, which may indicate active attempts to exploit this vulnerability.
