---
title: Coraza WAF Silent Argument Limit Bypass via Parameter Flooding
slug: 2026-10-coraza-argument-bypass
description: Coraza WAF silently drops parameters when the configured argument limit is reached, allowing attackers to evade security rules by flooding requests with filler parameters that force malicious payloads to be ignored by the WAF engine.
date: "2026-10-07T00:44:59Z"
lastmod: "2026-10-08T19:25:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-firewall
  - defense-evasion
  - parameter-flooding
  - security-bypass
  - denial-of-service
  - waf
  - coraza
vendors:
  - Coraza
products:
  - Coraza WAF (>= 3.0.0, <= 2026-07-28)
  - Coraza WAF (>= 3.0.0, < 3.8.1)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The vulnerability allows attackers to bypass security rules targeting ARGS by inflating the request's argument count, effectively rendering WAF rules invisible.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker... can crash the entire host process with a single request, using a payload well within default and recommended body size and argument-count limits.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-6r3q-mjv7-xr8m
  - https://github.com/corazawaf/coraza-ghsa-6r3q-mjv7-xr8m/pull/1
  - https://github.com/advisories/GHSA-6gcq-wc29-5xf2
action_plan:
  priority: immediate_escalation
  owners:
    - Security Engineering
    - Infrastructure Operations
  immediate_actions:
    - action: Upgrade Coraza WAF to the patched version identified in the July 2026 fix
      owner: Infrastructure Operations
      due: 24h
      evidence: Source provides fix in PR linked to the GHSA
  mitigation_plan:
    - priority: immediate
      action: Deploy compensating rules to block requests exceeding SecArgumentsLimit via ARGUMENTS_LIMIT_REACHED flag
      owner: Security Engineering
      addresses: Parameter flooding evasion
      evidence: Source provides recommended SecRule configuration for mitigation
updates:
  - at: "2026-10-08T19:25:56Z"
    level: L2
    summary: added coverage for Coraza WAF (>= 3.0.0, < 3.8.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6gcq-wc29-5xf2
---

Coraza WAF (versions 3.0.0 through July 2026) contains a critical flaw in its argument parsing logic where the engine silently drops parameters once the `SecArgumentsLimit` (default 1000) is exceeded. This behavior occurs in `AddGetRequestArgument`, `AddPostRequestArgument`, and `AddPathRequestArgument`. Because the WAF engine fails to trigger an error, flag, or audit-log event when an argument is dropped, security rules inspecting `ARGS`, `ARGS_GET`, `ARGS_POST`, or `ARGS_PATH` proceed to evaluate an incomplete request without alerting the operator.

Furthermore, the parser for `urlutil.ParseQuery` iterates over maps in a non-deterministic order. Attackers can inflate the number of arguments in a request URI beyond the limit, forcing the WAF to randomly discard parameters, including potential exploit payloads. Additionally, the POST urlencoded body processor historically bypassed the argument limit entirely, and JSON processors lacked enforcement, creating both evasion and memory-exhaustion (DoS) surfaces. This vulnerability effectively nullifies OWASP Core Rule Set (CRS) protections against common attacks like SQLi, XSS, and RCE.

## Attack Chain

1. Attacker identifies a target application protected by an unpatched Coraza WAF instance.
2. Attacker crafts a malicious payload (e.g., SQL injection) intended to trigger a blocked response.
3. Attacker appends a large number of 'filler' parameters (e.g., 9999 dummy key-value pairs) to the URI query string or POST body.
4. Coraza's parser processes the request and hits the `SecArgumentsLimit` threshold.
5. The engine silently discards a subset of the arguments to maintain the limit, failing to update the transaction state or log an error.
6. Due to Go's randomized map iteration, the malicious payload is dropped by the WAF before inspection in Phase 2.
7. The WAF engine evaluates the remaining (sanitized) arguments against `SecRule` definitions.
8. The WAF returns an `HTTP 200 OK` (or other benign status), allowing the malicious payload to reach the backend application.

## Impact

Successful exploitation allows attackers to bypass any WAF rule targeting request arguments. Empirical testing demonstrates that flooding a request with 10,000 arguments yields a bypass rate of approximately 94% against standard detection rules. This facilitates the execution of SQL injection, cross-site scripting, and remote code execution attacks against the underlying application. Because the evasion is silent and occurs at the WAF engine level, incident responders may be unaware that attacks are reaching the backend. The vulnerability also poses a significant risk of memory-exhaustion-based Denial of Service (DoS) due to the lack of enforcement in the JSON and urlencoded body processors.

## Recommendation

1. Upgrade all Coraza WAF deployments to the latest version (post-2026-07-28) which enforces `ArgumentLimit` globally and provides the `ARGUMENTS_LIMIT_REACHED` transaction flag.
2. If an immediate upgrade is not possible, implement compensating `SecRule` directives in the WAF configuration to block requests where the parameter count hits or exceeds the limit, ensuring that silent drops are converted into explicit rejections.
3. Monitor web server logs for requests containing an unusually high volume of parameters as an indicator of potential parameter flooding attempts.
