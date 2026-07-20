---
title: vLLM Denial of Service Vulnerability via M-RoPE Prompt Embeds (CVE-2026-55514)
slug: 2026-07-vllm-dos
description: A denial of service vulnerability, CVE-2026-55514, exists in vLLM versions from 0.12.0 up to, but not including, 0.24.0, allowing an authorized remote user to send a specially crafted `/v1/completions` request that leverages pure prompt embeds with an M-RoPE-enabled model to trigger an assertion failure, causing the vLLM server application to fatally crash.
date: "2026-07-20T19:14:15Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vllm
  - large-language-model
  - cve
vendors:
  - vLLM
products:
  - vLLM (>= 0.12.0, < 0.24.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Sending a pure prompt embeds payload in a `/v1/completions` request with a model using M-RoPE causes the EngineCore to fail an assertion and fatally crash, shutting down the entire server application.
    confidence_band: high
cves:
  - id: CVE-2026-55514
    cvss: 6.5
    epss: 0.0037
references:
  - https://github.com/advisories/GHSA-33cg-gxv8-3p8g
---

A critical denial of service vulnerability, identified as CVE-2026-55514, affects vLLM versions 0.12.0 through 0.23.x. The flaw arises when a vLLM server is configured with `--enable-prompt-embeds` and is running a model that utilizes M-RoPE (Multi-head Rotational Position Embedding). An authorized remote user can exploit this vulnerability by sending an HTTP POST request to the `/v1/completions` endpoint with a JSON payload where the `prompt` field is explicitly set to `null` and the `prompt_embeds` field contains any non-null data. This specific combination bypasses expected conditions within the `_init_mrope_positions` method in `GPUModelRunner.py`, causing an assertion `req_state.prompt_token_ids is not None` to fail. The assertion failure results in a fatal crash of the EngineCore, leading to the complete shutdown of the vLLM server application. This attack is described as "extremely easy" to perform and can be triggered by nearly verbatim examples from the official `prompt_embeds` documentation, accounting for model and connection details.

## Attack Chain

1. An attacker identifies a vulnerable vLLM server instance (versions 0.12.0 to 0.23.x) configured with `--enable-prompt-embeds` and running an M-RoPE-supported model.
2. The attacker obtains authorization to make requests to the `/v1/completions` endpoint on the target vLLM server.
3. The attacker crafts a malicious HTTP POST request targeting the `/v1/completions` endpoint.
4. Within the request's JSON body, the attacker sets the `prompt` field to `null` and provides non-null data for the `prompt_embeds` field.
5. The vLLM server receives and begins processing the specially crafted `/v1/completions` request.
6. During processing, the `_init_mrope_positions` method in `GPUModelRunner.py` is invoked.
7. The method attempts to execute an assertion `assert req_state.prompt_token_ids is not None`.
8. Due to the attacker's payload setting `prompt=null`, `req_state.prompt_token_ids` is `None`, causing the assertion to fail and the EngineCore to fatally crash, resulting in a denial of service for the entire application.

## Impact

This vulnerability leads to a complete denial of service for affected vLLM server applications. Any configuration where `--enable-prompt-embeds` is active and an M-RoPE-supported model is in use is vulnerable. An authorized remote attacker can trivially trigger this assertion failure, causing the EngineCore to crash and shutting down the entire server. This results in unavailability of the large language model service, disrupting any applications or users relying on it. The ease of exploitation means that systems are at high risk if left unpatched. There are no reported specific victim counts, but any organization using the affected vLLM versions could be targeted.

## Recommendation

* Upgrade vLLM to version 0.24.0 or later immediately to patch CVE-2026-55514.
* Monitor vLLM server logs for unexpected assertion failures or fatal EngineCore crashes, particularly those indicating `AssertionError: M-RoPE requires prompt_token_ids to be available.`.
* If immediate patching is not possible, consider implementing network-level filtering or WAF rules to detect and block HTTP POST requests to `/v1/completions` that contain a JSON body with `prompt: null` and a non-null `prompt_embeds` field.
