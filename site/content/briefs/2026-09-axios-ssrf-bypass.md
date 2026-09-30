---
title: Axios Fetch Adapter Fails to Enforce Redirect Limits
slug: 2026-09-axios-ssrf-bypass
description: 'The Axios fetch adapter fails to enforce the maxRedirects: 0 configuration, enabling redirect-based SSRF by allowing requests to follow unexpected internal redirects.'
date: "2026-09-30T16:27:51Z"
lastmod: "2026-09-30T16:28:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - prototype-pollution
  - javascript
  - nodejs
  - supply-chain
vendors:
  - Axios
products:
  - axios (< 1.18.1)
  - axios (>= 0.28.0, < 0.34.0)
  - axios (>= 1.15.1, < 1.20.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'An attacker who controls the initial URL or a redirecting server can cause a fetch-adapter request to follow a redirect even though the caller configured maxRedirects: 0.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability is a read-side gadget that turns an existing same-process pollution condition into altered request serialization or request failures.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-x97p-jq2g-jp4f
  - CVE-2026-101909
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: 'Audit codebases using Axios to identify instances where maxRedirects: 0 is used with the fetch adapter'
      owner: Development
      due: 72h
      evidence: 'Source documentation identifies usage of maxRedirects: 0 with fetch adapter as the vulnerability vector'
  mitigation_plan:
    - priority: immediate
      action: Update axios to version 1.18.1 or later
      owner: Development
      addresses: SSRF via fetch adapter redirect bypass
      evidence: Verification on axios 1.18.1 confirms fix in HTTP adapter behavior
updates:
  - at: "2026-09-30T16:28:01Z"
    level: L1
    summary: added coverage for axios (>= 0.28.0, < 0.34.0) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-x97p-jq2g-jp4f
---

The Axios library provides a `maxRedirects` configuration option, frequently used by developers to mitigate redirect-based Server-Side Request Forgery (SSRF) by setting the limit to `0`. While the standard Node.js HTTP adapter correctly respects this constraint, the `fetch` adapter implemented in `lib/adapters/fetch.js` ignores this setting. 

When applications rely on the `fetch` adapter, either through explicit configuration, environment-specific resolution (such as in Deno, Bun, or Cloudflare Workers), or automatic adapter selection, the library fails to pass a restrictive `redirect` mode to the underlying `fetch()` API. Consequently, the default runtime behavior of `redirect: 'follow'` takes precedence. This discrepancy allows attackers who can influence the initial request URL or provide a malicious redirecting server to bypass intended SSRF protections, leading to potential unauthorized access to internal resources or state-changing operations on internal endpoints reachable from the application environment.

## Impact

Successful exploitation allows for redirect-based SSRF, which may lead to the exposure of sensitive internal data or unauthorized modification of internal system states. The impact is significant for applications operating in cloud or serverless environments where network perimeter defenses are often bypassed by internal requests. If an internal service processes state-changing requests without additional authentication, an attacker can trigger unauthorized mutations by providing an open redirect or a malicious redirection chain that directs the application to the internal target.

## Recommendation

Detection and remediation should focus on identifying applications using the fetch adapter in security-sensitive contexts.

- Audit application code for usages of `axios.get()` or `axios.request()` that specify `maxRedirects: 0` without explicit `fetchOptions` to define redirect behavior.
- Where the fetch adapter is required, enforce manual redirect handling by setting `fetchOptions: { redirect: 'manual' }` in the axios configuration.
- If the application environment supports it, prefer the Node.js HTTP adapter for requests requiring strict adherence to redirect limits.
- Implement network-level egress filtering to prevent the application server from initiating connections to sensitive internal service segments (127.0.0.1, 169.254.169.254, or private RFC1918 ranges) unless explicitly required.
