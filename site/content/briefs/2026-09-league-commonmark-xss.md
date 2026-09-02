---
title: Stored XSS via Attribute Filter Bypass in league/commonmark
slug: 2026-09-league-commonmark-xss
description: An XSS vulnerability in league/commonmark allows attackers to execute arbitrary JavaScript by prepending a U+000C form feed character to malicious attribute names, bypassing security filters in the AttributesExtension.
date: "2026-09-02T00:00:45Z"
lastmod: "2026-09-02T00:00:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - php
  - supply-chain
  - denial-of-service
  - algorithmic-complexity
vendors:
  - thephpleague
products:
  - commonmark (>= 2.7.0, < 2.9.1)
  - commonmark (>= 0.6.0, < 2.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Stored cross-site scripting in any application that renders untrusted Markdown with AttributesExtension enabled.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This results in the validator failing to identify restricted attributes... leading to arbitrary JavaScript execution in the victim's browser.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker who can submit Markdown for conversion can use a comparatively small request to consume disproportionate CPU time.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-j8pm-gj4c-rq4x
action_plan:
  priority: elevated
  owners:
    - Development Team
    - Security Operations
  immediate_actions:
    - action: Upgrade league/commonmark to version 2.9.1 or later.
      owner: Development Team
      due: 48h
      evidence: Source provides 2.9.1 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Configure an explicit allow-list for the AttributesExtension.
      owner: Development Team
      addresses: XSS filter bypass
      evidence: Setting an explicit allow list takes the other branch of filterAttributes, which drops the form-feed name.
updates:
  - at: "2026-09-02T00:00:54Z"
    level: L2
    summary: added coverage for commonmark (>= 0.6.0, < 2.9.1)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-j8pm-gj4c-rq4x
---

The `AttributesExtension` for the `league/commonmark` library fails to correctly sanitize attributes when a U+000C form feed character (`\x0C`) is prepended to the attribute name. The library's `AttributesHelper` uses PHP's `trim()` function to clean input, but since `\x0C` is excluded from the default trim character list, the character is preserved. This results in the validator failing to identify restricted attributes (such as `onclick` or `onerror`) or unsafe `javascript:` URIs. Because the subsequent HTML renderer does not escape attribute names, browsers interpret the malformed tag as a valid HTML element containing the malicious handler or URI. This vulnerability affects `league/commonmark` versions 2.7.0 through 2.9.0 and persists even when developers enable recommended security configurations, such as disabling `allow_unsafe_links`.

## Attack Chain

1. Attacker crafts a Markdown payload containing a malicious attribute or URI, prepending a U+000C character (e.g., `{\x0Conclick="alert(1)"}`).
2. The `league/commonmark` parser encounters the attribute string during Markdown conversion.
3. The `AttributesHelper` matches the attribute string, including the leading `\x0C`, via regex.
4. The code calls PHP `trim()` on the attribute name, which fails to strip the `\x0C` character.
5. The library's `filterAttributes()` function compares the sanitized attribute name against an allow-list; the presence of the hidden `\x0C` causes string comparisons to fail, allowing the malicious attribute to pass.
6. The `HtmlElement` class serializes the attribute into the final HTML output without additional validation or escaping.
7. The target's browser parses the emitted HTML, treating the `\x0C` as whitespace and executing the attacker's JavaScript payload.

## Impact

Successful exploitation results in stored Cross-Site Scripting (XSS) in any application rendering untrusted Markdown using the `AttributesExtension`. Because payloads like `onerror` can be attached to image tags, the script executes automatically upon page load without requiring user interaction. This leads to session hijacking, unauthorized actions on behalf of the user, and potential account takeover.

## Recommendation

Prioritize patching and configuration changes to mitigate the risk of XSS exploitation.
* Upgrade `league/commonmark` to version 2.9.1 or later immediately.
* As a short-term workaround, define an explicit `allow` list for attributes (e.g., `['id', 'class', 'align']`) in the `AttributesExtension` configuration; this forces the library to reject attributes that do not match the allow-list regardless of prefix characters.
* Audit applications using `league/commonmark` to determine if the `AttributesExtension` is enabled and if inputs are retrieved from untrusted sources.
