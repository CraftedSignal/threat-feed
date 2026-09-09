---
title: Attribute Injection in @xmldom/xmldom via Element.setAttribute
slug: 2026-09-xmldom-attribute-injection
description: The @xmldom/xmldom library fails to validate attribute names during the use of Element.setAttribute, allowing attackers to inject malicious attributes into serialized XML output leading to potential XSS.
date: "2026-09-09T03:48:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xmldom:xmldom:*:*:*:*:*:*:*:*
tags:
  - xss
  - injection
  - vulnerability
  - web-application
products:
  - '@xmldom/xmldom (0.7.0 - 0.9.10)'
  - xmldom (<= 0.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: An attacker can terminate the current attribute and inject new ones by including quote and space characters in the attribute name.
    confidence_band: high
cves:
  - id: CVE-2026-83605
    epss: 0.00348
references:
  - https://github.com/advisories/GHSA-4w3w-2rp5-g8jm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83605
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Application Security
  immediate_actions:
    - action: Audit application code for use of Element.setAttribute with user-controlled input
      owner: Development Teams
      due: 48h
      evidence: Source identified setAttribute as the entry point for injection
  mitigation_plan:
    - priority: immediate
      action: 'Upgrade @xmldom/xmldom to 0.9.11 or 0.8.14 and enable requireWellFormed: true'
      owner: Development Teams
      addresses: CVE-2026-83605
      evidence: Fixed versions noted in vendor advisory
---

The @xmldom/xmldom library (CVE-2026-83605) contains an attribute injection vulnerability arising from inconsistent validation between its APIs. While the public `Document.createAttribute()` method correctly validates attribute names against the XML `QName` production, the commonly used `Element.setAttribute()` method calls a private `_createAttribute()` helper that performs no validation. 

The vulnerability allows an attacker to inject characters - such as quotes and spaces - into the attribute name parameter of `setAttribute()`, effectively terminating the intended attribute and injecting new ones (e.g., `onclick` event handlers) into the document tree. Because the library's `XMLSerializer` performs no validation by default, these injected attributes are rendered verbatim in the output. If this output is subsequently parsed by a browser, it can result in Cross-Site Scripting (XSS) or the overriding of security-critical attributes like `integrity` or `Content-Security-Policy`. This vulnerability affects versions of `@xmldom/xmldom` from 0.7.0 through 0.9.10, as well as the legacy `xmldom` package (<= 0.6.0). 

## Impact

Successful exploitation allows for arbitrary attribute injection when user-supplied input is reflected in attribute names. This poses a significant risk to web applications using this library to process or generate XML/HTML, as it can lead to XSS, bypass of security constraints, or unauthorized execution of JavaScript if the resulting XML is rendered as HTML in a browser context.

## Recommendation

- Upgrade to `@xmldom/xmldom` version 0.9.11 or 0.8.14 or later to access the new validation features.
- Implement the `requireWellFormed: true` option in all `XMLSerializer.serializeToString()` calls that process untrusted or partially user-controlled DOM content.
- Perform an audit of the codebase to identify all locations where user-provided strings are passed as the 'name' parameter to `setAttribute()`.
- Validate all attribute names against the XML `QName` production before calling `setAttribute()` if the library cannot be updated or if strict serialization cannot be enabled.
