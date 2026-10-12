---
title: Denial of Service Vulnerability in SGLang via Image Processing
slug: 2026-10-sglang-dos
description: SGLang versions 0.5.21 and earlier are vulnerable to a denial of service attack where attackers can trigger memory exhaustion by bypassing Pillow decompression bomb protections.
date: "2026-10-12T20:29:46Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:sglang:sglang:*:*:*:*:*:*:*:*
products:
  - SGLang (<= 0.5.21)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: SGLang through 0.5.21 contains a denial of service vulnerability that disables Pillow decompression bomb protection process-wide.
    confidence_band: high
cves:
  - id: CVE-2026-109229
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109229
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade SGLang to the latest available version to address the vulnerability in NanoNemotronVLImageProcessor.
      owner: IT Operations
      due: 72h
      evidence: SGLang through 0.5.21 is vulnerable to a denial of service attack.
  mitigation_plan:
    - priority: immediate
      action: Configure application-level memory limits and image input validation before processing.
      owner: IT Operations
      addresses: CVE-2026-109229
      evidence: Remote attackers can submit small, highly compressed images ... exhausting worker memory.
---

SGLang through version 0.5.21 contains a denial of service (DoS) vulnerability originating from the NanoNemotronVLImageProcessor component. The application improperly configures the Pillow imaging library by setting the global `Image.MAX_IMAGE_PIXELS` parameter to `None`. This action disables the library's built-in decompression bomb protection, which is designed to prevent excessive memory consumption when processing highly compressed image files that expand into massive pixel dimensions. Remote attackers can exploit this configuration by submitting specially crafted, small-file-size images with extreme pixel dimensions. When the SGLang worker processes these images, the decoding operation bypasses memory limits, leading to rapid memory exhaustion and the crashing of the worker process. This vulnerability allows for service degradation or complete denial of service against the inference or image processing pipeline.

## Impact

Successful exploitation results in service unavailability due to process-wide memory exhaustion. This impact is significant for organizations using SGLang in production environments for image-based AI or machine learning inference tasks. An attacker can repeatedly send malicious requests to deplete system resources, causing repeated worker failures and disrupting legitimate service operations.

## Recommendation

* Upgrade to a version of SGLang that restores or enforces strict memory bounds for the Pillow library.
* Implement input validation and file size limits at the application gateway or load balancer to reject suspicious images before they reach the SGLang processing logic.
* Monitor memory usage metrics for SGLang worker processes to identify anomalies indicating potential exploitation attempts or resource exhaustion.
