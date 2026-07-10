---
title: JustHTML XSS Vulnerability via Code Fence Breakout
slug: 2024-01-09-justhtml-xss
description: JustHTML versions 1.12.0 and earlier are vulnerable to cross-site scripting (XSS) by manipulating the contents of a <pre> element to inject HTML code outside of the intended code block, potentially leading to arbitrary JavaScript execution.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - justhtml
  - markdown
vendors:
  - JustHTML
products:
  - JustHTML
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5vp3-3cg6-2rq3
rules:
  - title: Detect JustHTML to_markdown XSS Payload in Web Logs
    description: Detects potential XSS attempts exploiting the JustHTML to_markdown vulnerability by searching for the specific payload pattern in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect JustHTML to_markdown XSS Payload in HTTP Request Body
    description: Detects potential XSS attempts exploiting the JustHTML to_markdown vulnerability by searching for the specific payload pattern in HTTP request bodies.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

JustHTML, a Python library for HTML manipulation, is susceptible to a cross-site scripting (XSS) vulnerability in versions 1.12.0 and earlier. This flaw occurs during the `to_markdown()` serialization of attacker-controlled `<pre>` content. The vulnerability allows an attacker to inject arbitrary HTML code outside the intended fenced code block by exploiting a weakness in how the library handles backticks within the `<pre>` tag. This bypasses the v1.12.0 Markdown hardening, which escaped HTML-significant characters for regular text nodes but not for the separate `<pre>` serialization path. This can lead to the execution of arbitrary JavaScript code when the resulting Markdown is rendered by a CommonMark/GFM-style renderer that allows raw HTML.

## Attack Chain

1. The attacker crafts malicious HTML content containing a `<pre>` tag with embedded backticks and HTML-like text.
2. The attacker supplies this crafted HTML to the `JustHTML()` constructor with `sanitize=True`.
3. The `to_markdown()` method is called on the `JustHTML` object.
4. The `to_markdown()` method processes the `&lt;pre>` tag and generates a fenced code block with a fixed delimiter of ``````` (three backticks).
5. Due to the fixed delimiter, the attacker-controlled content, containing a backtick run of length 3 or more, terminates the code block prematurely.
6. The remaining HTML-like text, such as `<img src=x onerror=alert(1)>`, appears outside the fenced code block in the resulting Markdown output.
7. The vulnerable markdown is rendered by a CommonMark/GFM-style renderer.
8. The injected HTML is treated as raw HTML, leading to the execution of the embedded JavaScript code.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary HTML and JavaScript code into applications that use `JustHTML(..., sanitize=True).to_markdown()` and render the output in Markdown contexts. This may lead to XSS, where the attacker can execute malicious scripts in the context of the victim's browser.  The number of affected applications is currently unknown, but any application using JustHTML for Markdown generation with user-supplied HTML is potentially vulnerable.

## Recommendation

*   Upgrade to a version of `justhtml` greater than 1.12.0 to remediate the vulnerability as advised in the advisory.
*   Sanitize user-provided HTML input before passing it to `JustHTML` to mitigate the risk of malicious code injection.
*   If upgrading is not immediately feasible, consider implementing custom escaping logic for `<pre>` content before passing it to `to_markdown()` to prevent code fence breakouts.
