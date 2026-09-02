---
title: Mistune Denial of Service via Markdown Recursion
slug: 2026-09-mistune-dos
description: Mistune versions 3.3.0 through 3.3.2 are susceptible to a denial of service attack via uncontrolled recursion during the rendering of deeply nested emphasis markers.
date: "2026-09-02T18:03:41Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:mistune_project:mistune:3.3.0:*:*:*:*:python:*:*
  - cpe:2.3:a:mistune_project:mistune:3.3.1:*:*:*:*:python:*:*
  - cpe:2.3:a:mistune_project:mistune:3.3.2:*:*:*:*:python:*:*
tags:
  - denial-of-service
  - markdown
  - python
  - vulnerability
products:
  - mistune (>= 3.3.0, < 3.3.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: By submitting Markdown containing approximately 1,000 consecutive asterisk characters, an attacker causes the Python process to crash with RecursionError.
    confidence_band: high
cves:
  - id: CVE-2026-76098
    cvss: 7.5
    epss: 0.00278
references:
  - https://github.com/advisories/GHSA-6m44-fpc8-c3rq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76098
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade mistune package to 3.3.3 or later in all production environments.
      owner: IT Operations
      due: 24h
      evidence: Source states remediation involves updating to versions >= 3.3.3.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF or application-layer input validation rules to reject payloads with excessive repeating characters.
      owner: Application Security
      addresses: CVE-2026-76098
      evidence: Source identifies 1,000 asterisks as the trigger threshold.
---

Mistune versions 3.3.0 through 3.3.2 are vulnerable to a Denial of Service (DoS) attack stemming from uncontrolled recursion during the HTML rendering process. The vulnerability exists within the InlineParser's emphasis delimiter processing, which generates deeply nested strong and emphasis HTML tokens when provided with repetitive character sequences. Specifically, an input containing approximately 1,000 consecutive asterisk characters triggers the generation of roughly 500 levels of nested tokens. During the rendering phase, the HTMLRenderer.render_tokens() method processes these tokens recursively. Given that each nesting level consumes multiple stack frames, the rendering process exceeds the Python default recursion limit (typically 1,000), resulting in a RecursionError and subsequent crash of the host process. This vulnerability affects all core APIs, including markdown() and html(), and is reachable via any application endpoint that accepts user-supplied Markdown content for rendering.

## Attack Chain

1. Attacker identifies a web application or backend service that utilizes Mistune v3.3.0-3.3.2 to parse user-generated Markdown input.
2. Attacker crafts a malicious payload consisting of approximately 1,000 consecutive asterisk (*) characters.
3. The web application receives the malicious payload via a standard input method (e.g., forum post, comment, or API request).
4. The application passes the malicious string to the vulnerable Mistune library (e.g., mistune.html() or mistune.markdown()).
5. Mistune's InlineParser parses the asterisks and creates an excessive tree of nested emphasis/strong tokens in memory.
6. The HTMLRenderer initiates a recursive render process to convert the token tree into HTML output.
7. The recursion depth exceeds Python's sys.getrecursionlimit() due to the stack frame overhead of the renderer.
8. A RecursionError is raised, causing the Python process to crash and resulting in a denial of service for that process.

## Impact

The vulnerability carries a CVSS 3.1 score of 7.5. Successful exploitation allows an unauthenticated remote attacker to crash the application process, leading to a denial of service for all users sharing that process. This is particularly impactful for multi-tenant web applications or services running in shared worker environments, where a single request can terminate the entire service instance.

## Recommendation

Prioritize the following actions to mitigate CVE-2026-76098:

- Upgrade the mistune library to version 3.3.3 or later immediately, as this version contains the necessary logic to prevent excessive nesting.
- For environments unable to update immediately, implement a pre-processing filter on input strings to detect and reject Markdown payloads containing excessive consecutive special characters (e.g., a sequence of >50 asterisks).
- Implement request-level timeouts for all services invoking Markdown rendering to limit the duration and impact of resource-intensive parsing operations.
- Evaluate the necessity of custom renderers that use iterative, stack-based processing instead of recursive calls to handle nested Markdown elements safely.
