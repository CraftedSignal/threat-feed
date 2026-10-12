---
title: Unbounded Memory Allocation in SGLang
slug: 2026-10-sglang-dos
description: SGLang versions up to 0.5.21 are vulnerable to a denial-of-service condition via an unbounded memory allocation issue in the /v1/audio/transcriptions endpoint.
date: "2026-10-12T15:43:13Z"
lastmod: "2026-10-12T15:43:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:sglang:sglang:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - sglang
vendors:
  - SGLang
products:
  - SGLang (<= 0.5.21)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can send concurrent large multipart uploads... to crash the HTTP/tokenizer worker and deny service.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109225
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109226
rules:
  - title: Detect CVE-2026-109225 Exploitation - Large POST Requests to /v1/audio/transcriptions
    description: Detects potential DoS attempts against CVE-2026-109225 by identifying unusually large POST requests directed at the audio transcription endpoint.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for large POST requests to /v1/audio/transcriptions.
      owner: Detection Engineering
      due: 48h
      evidence: SGLang unbounded memory allocation vulnerability
  mitigation_plan:
    - priority: immediate
      action: Configure edge reverse proxy or load balancer to enforce a strict client_max_body_size for the /v1/audio/transcriptions endpoint.
      owner: IT Operations
      addresses: CVE-2026-109225
      evidence: Source reporting of unbounded memory allocation
updates:
  - at: "2026-10-12T15:43:30Z"
    level: L1
    summary: added coverage for SGLang (<= 0.5.21)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-109226
---

SGLang through version 0.5.21 contains an unbounded memory allocation vulnerability that allows unauthenticated remote attackers to exhaust system memory. The vulnerability exists within the /v1/audio/transcriptions endpoint, which fails to properly validate the size of incoming multipart file uploads. Because the application reads the entirety of these files into memory prior to performing size validation or processing, an attacker can leverage concurrent, oversized upload requests to trigger a service crash. This results in the denial of service for the HTTP and tokenizer worker components, potentially impacting the availability of the model serving infrastructure. Defenders should prioritize updating to a patched version or implementing request size limits at the load balancer or reverse proxy layer to mitigate potential exploitation.

## Impact

The vulnerability poses a high risk to availability, specifically for infrastructure relying on the affected SGLang audio transcription endpoint. Successful exploitation results in a service crash of the worker processes, denying legitimate users access to transcription services. This impacts any sector deploying SGLang for speech processing, particularly those with public-facing API interfaces.

## Recommendation

* Implement request body size limits at the edge (e.g., Nginx client_max_body_size) to block excessively large multipart uploads before they reach the SGLang application.
* Monitor webserver logs for high-frequency or large POST requests targeting the /v1/audio/transcriptions endpoint.
* Patch SGLang to the version addressing this memory allocation flaw as soon as vendor guidance is released.
