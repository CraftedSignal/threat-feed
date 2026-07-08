---
title: '`lxml_html_clean` `javascript:` URL Bypass via `xlink:href` (CVE-2026-49825)'
slug: 2026-07-lxml-xss-bypass
description: The `lxml_html_clean.Cleaner` Python library, and the `lxml.html.clean` module in `lxml`, fails to strip `javascript:`, `vbscript:`, and `data:` URLs from namespaced attributes like `xlink:href` when configured with `safe_attrs_only=False`. This vulnerability, identified as CVE-2026-49825, is a form of stored Cross-Site Scripting (XSS) that allows malicious JavaScript to bypass sanitization, enabling client-side code execution if an application processes and renders untrusted HTML containing such payloads.
date: "2026-07-08T20:28:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - vulnerability
  - python
  - web-application
  - html-sanitization
vendors:
  - lxml
  - lxml_html_clean
products:
  - lxml <= 6.1.0
  - lxml_html_clean < 0.4.5
  - lxml.html.clean
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: any browser that follows the SVG-anchor specification will execute the JavaScript when the rendered link is clicked
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: A caller that uses `Cleaner` to neutralise untrusted HTML [...] will silently pass `javascript:` payloads carried on `xlink:href` through to victim renders.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4jhm-jv67-739f
---

A critical vulnerability (CVE-2026-49825) has been identified in the `lxml_html_clean.Cleaner` library (versions `<= 0.4.4`) and the legacy `lxml.html.clean` module within `lxml` (versions `<= 6.1.0`). This flaw allows `javascript:`, `vbscript:`, and `data:` URLs to bypass HTML sanitization when present in namespaced attributes, specifically `xlink:href`, and when the `Cleaner` is instantiated with `safe_attrs_only=False`. The root cause is `lxml`'s `defs.link_attrs` allow-list, which `iterlinks()` relies on, not including `xlink:href`, preventing the `_remove_javascript_link` function from being invoked for these attributes. This enables stored Cross-Site Scripting (XSS) attacks in web applications that use these libraries for sanitizing user-supplied HTML, potentially leading to client-side code execution in victim browsers. The bug affects applications that aim for lenient attribute handling but still expect URL scheme scrubbing.

## Attack Chain

1. An attacker crafts a malicious HTML payload containing a `javascript:` URL embedded within an `xlink:href` attribute, such as `<svg><a xlink:href="javascript:alert(document.domain)">click me</a></svg>`.
2. The attacker submits this malicious HTML to a web application (e.g., a forum post, comment section) that uses `lxml_html_clean.Cleaner` or `lxml.html.clean` to sanitize user input.
3. The `Cleaner` instance is configured with `safe_attrs_only=False`, a documented option for allowing custom attributes while still expecting URL scheme scrubbing.
4. Due to the vulnerability (CVE-2026-49825), the `Cleaner` fails to identify and strip the `javascript:` URL from the `xlink:href` attribute because it's not present in its internal `link_attrs` allow-list.
5. The unsanitized malicious HTML payload is successfully stored in the application's database or file system.
6. A legitimate user accesses the web application page containing the stored malicious content, and their browser renders the SVG or MathML anchor element.
7. The user clicks on the rendered link.
8. The browser executes the embedded `javascript:` URL in the context of the victim's domain, leading to client-side code execution (Stored XSS). This can result in session hijacking, data exfiltration, or further attacks.

## Impact

Successful exploitation of CVE-2026-49825 leads to stored Cross-Site Scripting (XSS), allowing attackers to execute arbitrary JavaScript in the context of a victim's browser session. This can result in sensitive data theft (e.g., session cookies, credentials), defacement of web pages, redirection to malicious sites, or further client-side attacks. The severity is rated as 8.2 / High (CVSS 3.1: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N), emphasizing that the vulnerability is network-exploitable with low attack complexity, requires user interaction (clicking the link), but changes the security scope and can lead to high confidentiality impact. Exploitation is conditional on the `safe_attrs_only=False` configuration.

## Recommendation

* Immediately update `lxml_html_clean` to version `0.4.5` or higher to remediate CVE-2026-49825, which addresses the flaw in URL scheme stripping.
* If still using `lxml.html.clean`, ensure your `lxml` library version incorporates the fix for CVE-2026-49825, or switch to the maintained `lxml_html_clean` library.
* Review all instances of `lxml_html_clean.Cleaner` or `lxml.html.clean` instantiation within your applications, especially those configured with `safe_attrs_only=False`, to ensure they are adequately sanitizing all user-supplied HTML.
* Implement Content Security Policies (CSPs) with strict `script-src` directives to mitigate the impact of any successful XSS attempts, even if this vulnerability is exploited.
