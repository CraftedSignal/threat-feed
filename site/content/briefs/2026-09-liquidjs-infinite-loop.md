---
title: Denial of Service Vulnerability in LiquidJS strip_html Filter
slug: 2026-09-liquidjs-infinite-loop
description: An infinite loop vulnerability in the LiquidJS strip_html filter, tracked as CVE-2026-61556, allows attackers to trigger a process-wide denial of service by providing specific malformed HTML strings.
date: "2026-09-03T18:04:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:liquidjs:liquidjs:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
vendors:
  - LiquidJS
products:
  - liquidjs (>= 10.26.0, < 10.27.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: This results in a denial of service (DoS). Although a ReDoS vulnerability has previously been reported, this issue can cause a more severe impact.
    confidence_band: high
cves:
  - id: CVE-2026-61556
    epss: 0.00315
references:
  - https://github.com/advisories/GHSA-m7fp-h3p4-hr49
  - https://cwe.mitre.org/data/definitions/835.html
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade liquidjs to 10.27.1
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-61556 patch availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade liquidjs to version 10.27.1 or later
      owner: IT Operations
      addresses: CVE-2026-61556
      evidence: Source Recommended Fix
---

LiquidJS versions 10.26.0 through 10.27.0 contain a vulnerability in the `strip_html` filter that leads to an infinite loop, resulting in a denial of service (DoS). The flaw exists in `src/filters/html.ts` due to improper state management during string parsing. When an input string contains a `<` character that is not followed by a matching `>` (or a corresponding closing tag for script, style, or comment blocks), the loop index `i` fails to increment. Because the loop logic repeatedly encounters the same unclosed `<` at the same index, the process hangs indefinitely. This vulnerability is highly accessible, requiring only a two-character input (e.g., "a<") to exhaust system resources. Given the prevalence of template engines in web applications, this vulnerability poses a significant risk for server-side resource exhaustion.

## Attack Chain

1. Attacker identifies a web application or internal service utilizing LiquidJS to render user-supplied input.
2. Attacker crafts a malicious payload containing an unclosed HTML tag structure, such as "a<" or similar variants lacking a closing `>`.
3. Attacker submits the malicious input to an application endpoint that triggers the `strip_html` filter processing.
4. The LiquidJS engine initializes the `strip_html` function with the attacker-controlled input.
5. The function's `while` loop locates the `<` at index 1 but fails to find a matching closing delimiter.
6. The logic checks `if (i === lt)`, which remains true because `i` never advances, returning the control flow to the start of the loop.
7. The process consumes CPU cycles continuously in an infinite loop.
8. The application worker process hangs, leading to a denial of service for that specific thread or process.

## Impact

Successful exploitation results in a complete denial of service for the affected application process. Because the infinite loop is triggered by minimal input (two characters), an attacker can easily overwhelm web servers or template-rendering services, leading to system unavailability and resource exhaustion. This impacts any sector deploying LiquidJS in environments that process untrusted user input through the `strip_html` filter.

## Recommendation

1. Upgrade the `liquidjs` package to version 10.27.1 or later immediately to include the patch for CVE-2026-61556.
2. Audit applications using `strip_html` to determine if user-controlled input is passed directly to this filter without pre-validation.
3. Implement resource monitoring (CPU usage per worker process) to detect stalled processes indicative of DoS attempts.
