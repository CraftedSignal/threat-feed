---
title: Quadratic-time Denial of Service in probe-image-size SVG Parser
slug: 2026-10-probe-image-size-dos
description: The probe-image-size package is vulnerable to a denial-of-service attack due to a regular expression exhibiting quadratic time complexity when processing maliciously crafted SVG payloads.
date: "2026-10-03T04:50:24Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:probe-image-size_project:probe-image-size:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - nodejs
  - software-vulnerability
products:
  - probe-image-size (<= 7.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Processing a crafted buffer blocks the Node.js event loop at 100% CPU for the whole duration.
    confidence_band: high
cves:
  - id: CVE-2026-104861
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-gjj5-9665-rwrc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104861
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade probe-image-size to a version later than 7.3.0
      owner: IT Operations
      due: 24h
      evidence: Affected packages list indicates versions <= 7.3.0 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Implement strict file size limits and rate limiting on image processing endpoints
      owner: Security Engineering
      addresses: CVE-2026-104861
      evidence: Source notes that input size contributes to the quadratic time complexity
---

The probe-image-size package (v7.3.0 and earlier) is vulnerable to a Denial of Service (DoS) attack caused by an inefficient regular expression used to scan SVG headers. The regex `/<[-_.:a-zA-Z0-9][^>]*>/` triggers quadratic time complexity when it processes an input buffer containing a high density of `<` characters without corresponding `>` closing tags. Because the parser restarts the scan at every `<` position and traverses to the end of the input, a relatively small payload can force the Node.js process to consume 100% CPU.

This vulnerability impacts the synchronous (`probe.sync()`) and streaming (`probe(stream)`, `probe(url)`) parsing paths. In production environments such as link unfurlers or image processing proxies, the CPU exhaustion causes the Node.js event loop to block, rendering the service unresponsive. Attackers can exploit this by submitting a simple URL pointing to a crafted malicious SVG.

## Impact

Successful exploitation leads to complete service unavailability of the affected application. Because the vulnerability affects image upload validators and link preview services, the impact is severe for web-facing applications. A minimal number of concurrent requests is sufficient to crash or hang a Node.js process, and the ability to trigger this remotely via URL makes it highly accessible for exploitation.

## Recommendation

Prioritize the immediate upgrade of the `probe-image-size` package to a version beyond 7.3.0. For applications where immediate patching is not possible, implement strict validation on input size and content before passing data to the `probe-image-size` library. Additionally, deploy rate-limiting on endpoints that accept remote URLs for image processing to mitigate the impact of CPU-exhaustion attacks.
