---
title: Remote Code Execution in Astro via libheif AVIF Optimization
slug: 2026-09-astro-rce
description: A critical vulnerability in the libheif library used by the Astro framework allows unauthenticated remote code execution when processing maliciously crafted AVIF images.
date: "2026-09-08T21:48:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Astro
products:
  - Astro (< 7.2.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A vulnerability in libheif, used by the default Sharp image service in Astro, can lead to remote code execution when a malicious AVIF image is optimized.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-26w7-cxv4-gfx2
  - https://github.com/withastro/astro/releases/tag/astro@7.2.8
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Astro to version 7.2.8 or later
      owner: IT Operations
      due: 24h
      evidence: The fix was released in Astro 7.2.8, which requires Sharp 0.35.4.
  mitigation_plan:
    - priority: immediate
      action: Disable image optimization for untrusted sources
      owner: IT Operations
      addresses: GHSA-26w7-cxv4-gfx2
      evidence: Projects are affected when an attacker can cause Astro to process an untrusted AVIF image.
---

A critical vulnerability exists in the Astro web framework due to the underlying libheif library used by the default Sharp image service. The vulnerability, tracked as GHSA-26w7-cxv4-gfx2, arises from out-of-bounds read and write operations (CWE-125 and CWE-787) during the optimization of AVIF image files. An attacker can achieve remote code execution (RCE) by supplying a specially crafted, malicious AVIF image to an Astro application that is configured to process or optimize user-uploaded or externally sourced imagery. This vulnerability allows for unauthenticated exploitation with no user interaction required. The fix was introduced in Astro 7.2.8, which mandates the use of Sharp 0.35.4. Given the nature of RCE, this poses a significant risk to the integrity and availability of any internet-facing Astro site that supports image transformation.

## Attack Chain

1. The attacker identifies an Astro-based web application that utilizes the default Sharp image service for on-the-fly image optimization.
2. The attacker crafts a malicious AVIF image file specifically designed to trigger out-of-bounds memory access (read/write) within the libheif decoding process.
3. The attacker uploads the malicious image to the target application or forces the application to fetch the malicious file via an image transformation URL.
4. The Astro application invokes the Sharp service to optimize or resize the provided image.
5. The underlying libheif library processes the malicious AVIF headers or bitstream.
6. The out-of-bounds memory corruption triggers a controlled overwrite of memory or flow redirection.
7. The process executes arbitrary attacker-supplied code or shell commands within the context of the web server process.
8. The final objective is achieved, resulting in full system compromise or persistence on the affected server.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary code on the web server with the privileges of the Astro application process. This can lead to full compromise of the application environment, exfiltration of sensitive configuration data or user information, and service disruption. The CVSS score for this vulnerability is 9.8, indicating maximum severity.

## Recommendation

1. Upgrade the Astro framework to version 7.2.8 or later immediately, which bundles the patched Sharp 0.35.4 library.
2. Implement strict input validation or file type allowlisting for any user-uploaded content processed by the image service.
3. If immediate patching is not possible, disable the image transformation service for untrusted or external image sources.
4. Inspect web server access logs for anomalous file upload requests or URI-encoded strings indicative of file manipulation prior to the application of the patch.
