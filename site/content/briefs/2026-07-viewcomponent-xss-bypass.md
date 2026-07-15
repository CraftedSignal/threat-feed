---
title: ViewComponent HTML-Safety Bypass Leads to Cross-Site Scripting (CVE-2026-54498)
slug: 2026-07-viewcomponent-xss-bypass
description: A critical HTML-safety bypass vulnerability, CVE-2026-54498, exists in ViewComponent versions prior to 4.12.0, allowing attackers to inject raw HTML via the `around_render` method, bypassing standard escaping and leading to Cross-Site Scripting (XSS) in affected Ruby on Rails applications.
date: "2026-07-15T22:52:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - ruby
  - vulnerability
  - client-side-scripting
vendors:
  - ViewComponent
products:
  - ViewComponent (>= 4.0.0, < 4.12.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A downstream application defines a component that uses `around_render` for tracing, layout wrapping, feature-flag fallback, error fallback, or instrumentation. If the hook returns a string containing request data, model attributes, CMS content, markdown output, or other attacker-controlled values, the value can be rendered as raw HTML.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: If `message` is user-controlled, scriptable HTML reaches the browser.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: ""
    evidence: '`ViewComponent::Base#around_render` can return HTML-unsafe strings that bypass the escaping behavior applied to normal `#call` return values.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-97jw-64cj-jc58
---

A high-severity HTML-safety bypass vulnerability (CVE-2026-54498) has been identified in `ViewComponent` versions 4.0.0 through 4.11.x, published on July 15, 2026. This flaw allows a specially crafted `around_render` method within a ViewComponent to return HTML-unsafe strings, thereby circumventing the automatic escaping applied to normal `#call` return values. Attackers can leverage this bypass to inject arbitrary client-side script (XSS) when an application uses `around_render` to wrap, replace, or conditionally return content that incorporates user-controlled data. The vulnerability is exacerbated in collection rendering (`ViewComponent::Collection#render_in`), where the combined output from multiple components is erroneously marked as `html_safe`, enabling raw, malicious HTML to be treated as trusted content and executed in the user's browser. This poses a significant risk to the integrity of web applications relying on affected ViewComponent versions.

## Attack Chain

1. An attacker identifies a target application using `ViewComponent` and a vulnerable component that overrides the `around_render` method.
2. The vulnerable `around_render` method is designed to return or wrap attacker-influenced HTML-unsafe content, such as a user-supplied message or dynamic data from a database.
3. The attacker crafts a malicious input (e.g., `<img src=x onerror=alert(1)>`) that, when processed by the application, will be included in the content returned by the `around_render` method.
4. The application renders the component, invoking the `around_render` method. Due to the vulnerability, the `around_render` method's output is not passed through the necessary HTML-escaping boundary.
5. If the component is rendered as part of a collection, the raw, unsafe output from multiple components is joined and then incorrectly marked as `html_safe` by `ViewComponent::Collection#render_in`.
6. The browser receives the server response containing the raw, unescaped malicious HTML, which it interprets and executes, leading to Cross-Site Scripting (XSS).
7. Successful execution enables various impacts, including session/token theft, authenticated actions as the victim, data exfiltration, or credential phishing within the trusted application origin.

## Impact

Successful exploitation of CVE-2026-54498 results in Cross-Site Scripting (XSS) within applications utilizing affected ViewComponent versions. Depending on the application's context and configuration, this can lead to severe consequences. Attackers could steal user session cookies or authentication tokens, perform authenticated actions on behalf of the victim, bypass Cross-Site Request Forgery (CSRF) protections, exfiltrate sensitive page data, or conduct credential phishing and UI redressing attacks from within the legitimate application domain. The risk is particularly elevated for applications that render components through `ViewComponent::Collection`, as this path actively marks raw malicious HTML as `html_safe`, preventing any subsequent security controls from sanitizing the output.

## Recommendation

* **Patch CVE-2026-54498 immediately** by upgrading `rubygems/view_component` to version 4.12.0 or later.
* **Review codebases for vulnerable patterns** where `around_render` returns or wraps user-controlled, HTML-unsafe content. Specifically inspect components that use `around_render` for tracing, layout wrapping, feature-flag fallbacks, or instrumentation.
* **Implement strict input sanitization and output encoding** at the application layer for all user-controlled data, especially when displayed in HTML contexts, even after patching.
