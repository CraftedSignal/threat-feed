---
title: Unauthenticated Remote Code Execution in Next.js Image Optimization API
slug: 2026-09-nextjs-rce
description: A critical vulnerability in the libheif dependency used by Next.js allows unauthenticated attackers to achieve remote code execution via malicious AVIF image uploads.
date: "2026-09-08T21:48:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - web-application
  - nextjs
vendors:
  - Vercel
products:
  - Next.js (>= 10.0.0, < 15.5.24)
  - Next.js (>= 16.0.0, < 16.3.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can exploit this via the network to execute arbitrary code.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2xp9-vwfh-vxw4
  - https://github.com/vercel/next.js/releases/tag/v15.5.24
  - https://github.com/vercel/next.js/releases/tag/v16.3.3
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Next.js to 15.5.24 or 16.3.3
      owner: IT Operations
      due: 24h
      evidence: Source advisory specifies these versions as patched
  mitigation_plan:
    - priority: immediate
      action: Disable AVIF image optimization in next.config.js
      owner: IT Operations
      addresses: Vulnerability in libheif/sharp image optimization
      evidence: Source advisory recommends disabling AVIF optimization until patches are applied
---

A critical remote code execution (RCE) vulnerability exists in the Next.js framework, specifically within its image optimization API. The vulnerability is rooted in the third-party `libheif` library, which is utilized by the `sharp` package to process AVIF image files. An unauthenticated attacker can trigger this vulnerability by submitting a maliciously crafted AVIF file to the Next.js image optimization endpoint. The flaw enables the execution of arbitrary code within the context of the application process. This vulnerability affects Next.js versions 10.0.0 through 15.5.23 and 16.0.0 through 16.3.2. As a result of the severity, defenders should prioritize patching or implementing the recommended mitigation immediately to prevent potential system compromise and data exfiltration.

## Attack Chain

1. Attacker identifies a target application utilizing Next.js for web hosting.
2. Attacker crafts a malicious AVIF image file containing a payload designed to exploit memory corruption in `libheif`.
3. Attacker sends an HTTP POST or GET request to the Next.js image optimization API endpoint (typically `/api/next/image` or similar paths handling image transformation).
4. The Next.js application receives the malicious image file and passes it to the `sharp` library for optimization/processing.
5. The `sharp` library invokes the vulnerable `libheif` code to parse the AVIF file.
6. Memory corruption occurs during the parsing of the malicious image, allowing the attacker to overwrite sensitive memory structures.
7. The attacker's payload executes within the context of the application server.
8. Final objective achieved: Remote code execution, facilitating potential exfiltration of environment variables, source code, or lateral movement into the internal network.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to achieve full remote code execution on the server hosting the Next.js application. This compromises the confidentiality, integrity, and availability of the application and its underlying infrastructure. Given the ubiquity of Next.js in modern web development, this vulnerability poses a high risk to a vast number of enterprise, government, and consumer-facing web platforms.

## Recommendation

1. Immediately upgrade Next.js to the patched versions: 15.5.24 or 16.3.3.
2. If an immediate upgrade is not feasible, disable AVIF support in the Next.js image configuration to mitigate the attack vector.
3. Deploy WAF rules to inspect and filter suspicious image upload requests targeting image optimization endpoints.
4. Conduct a review of application logs for anomalous requests to the image optimization API, specifically looking for high-frequency or large-payload image uploads.
