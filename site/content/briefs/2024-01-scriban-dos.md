---
title: Scriban Template Engine LoopLimit Bypass Vulnerability
slug: 2024-01-scriban-dos
description: Scriban's LoopLimit can be bypassed by crafted template expressions, allowing attackers to perform resource exhaustion through CPU or memory amplification, leading to denial of service.
date: "2024-01-27T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - scriban
  - dos
  - template-injection
vendors:
  - Scriban
products:
  - Scriban Template Engine
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-c875-h985-hvrc
rules:
  - title: Detect Scriban Template Rendering with Large Range and Array Size
    description: Detects Scriban template rendering processes that use a large numerical range piped to the array.size function, indicative of a LoopLimit bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
  - title: Detect Scriban Template Rendering with Large String Multiplication
    description: Detects Scriban template rendering processes that perform large string multiplications, indicating a potential memory amplification attack.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Scriban template engine is vulnerable to a denial-of-service attack due to a bypass in its `LoopLimit` functionality. This vulnerability, affecting Scriban versions prior to 7.0.0, allows attackers to craft template expressions that bypass the configured loop limits, leading to excessive CPU or memory consumption. The issue stems from the fact that `LoopLimit` only applies to script loop statements and not to expensive iteration performed inside operators and built-in functions such as `array.size` and string multiplication. An attacker can exploit this by submitting a single expression, like `{{ 1..1000000 | array.size }}` for CPU exhaustion or `{{ 'A' * 200000000 }}` for memory amplification, even when `LoopLimit` is set to a small value. This vulnerability impacts applications using Scriban with untrusted template content, including template-as-a-service systems, CMS, and email rendering systems.

## Attack Chain

1.  An attacker crafts a malicious Scriban template containing an expression designed to bypass `LoopLimit`. Example: `{{ 1..1000000 | array.size }}` or `{{ 'A' * 200000000 }}`.
2.  The attacker submits the malicious template to a vulnerable application that uses Scriban for template processing.
3.  The application parses the template using `Template.Parse()`.
4.  The application renders the template using `template.Render(context)` with a specified `LoopLimit` in `TemplateContext`.
5.  The `array.size` function (or string multiplication) is invoked, leading to a large number of iterations or memory allocations *without* respecting the `LoopLimit`.
6.  The application's CPU or memory resources are exhausted due to the uncontrolled iteration or allocation.
7.  The application becomes unresponsive or crashes, resulting in a denial-of-service condition.

## Impact

The vulnerability allows for uncontrolled resource consumption, leading to denial-of-service conditions. Any application that accepts attacker-controlled templates and relies on `LoopLimit` is vulnerable. Observed damage includes CPU exhaustion and memory amplification. Vulnerable systems could include template-as-a-service platforms, content management systems (CMS), and email rendering systems. A successful attack can cause application downtime, impacting availability and potentially leading to data loss or corruption if the system crashes during critical operations.

## Recommendation

*   Upgrade Scriban to version 7.0.0 or later to address the vulnerability.
*   Implement additional safeguards to limit the resources available to template rendering, such as setting CPU and memory limits.
*   Implement input validation on templates to detect and reject potentially malicious expressions. Specifically, look for large ranges used in conjunction with `array.size`, or excessively large string multiplications. Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor application resource usage (CPU, memory) for unusual spikes during template rendering. Enable process monitoring and alerting to detect processes consuming excessive resources.
