---
title: XML Injection Vulnerability in @xmldom/xmldom via Processing Instruction Targets
slug: 2026-09-xmldom-injection
description: The @xmldom/xmldom library fails to validate the target parameter in createProcessingInstruction, enabling attackers to break out of XML processing instructions and inject arbitrary content when serializing with the requireWellFormed flag.
date: "2026-09-08T21:50:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xmldom:xmldom:*:*:*:*:*:node.js:*:*
tags:
  - injection
  - xss
  - xxe
  - vulnerability
vendors:
  - xmldom
products:
  - '@xmldom/xmldom (<= 0.8.14)'
  - '@xmldom/xmldom (0.9.0 - 0.9.11)'
  - xmldom (<= 0.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Applications that create processing instructions with user-controlled target strings and serialize the result are vulnerable to XML injection.
    confidence_band: high
cves:
  - id: CVE-2026-83616
    epss: 0.00348
references:
  - https://github.com/advisories/GHSA-c7q8-3ch8-vqpv
  - https://www.w3.org/TR/xml/#NT-Name
action_plan:
  priority: elevated
  owners:
    - Development Team
  immediate_actions:
    - action: Audit codebase for usage of Document.createProcessingInstruction with user-supplied input
      owner: Development Team
      due: 72h
      evidence: Source document identifies user-controlled target strings as the primary injection vector
  mitigation_plan:
    - priority: immediate
      action: 'Enable requireWellFormed: true in all XMLSerializer.serializeToString calls processing untrusted data'
      owner: Development Team
      addresses: CVE-2026-83616
      evidence: Fix Applied section mandates explicit opt-in to the serializer validation
---

The @xmldom/xmldom library is susceptible to an XML injection vulnerability (CVE-2026-83616) due to insufficient validation of the target parameter in the `Document.createProcessingInstruction()` method. When developers use the `requireWellFormed: true` option in `XMLSerializer.serializeToString()`, the library fails to properly sanitize the processing instruction (PI) target. Specifically, it does not check for the `>` character, which prematurely terminates the processing instruction (`<?target data?>`). 

An attacker controlling the input to the target parameter can inject arbitrary XML elements, including `<script>` tags, into the serialized output. If this output is subsequently served as XHTML or processed by a downstream XML parser, it may lead to Cross-Site Scripting (XSS) or XML External Entity (XXE) injection attacks. The protection is not enabled by default, requiring developers to explicitly opt-in to the `requireWellFormed` mode, which remains incomplete in its validation logic across various versions of the library.

## Impact

Successful exploitation allows for the injection of arbitrary XML structure, leading to potential XSS in browser-based applications and XXE vulnerabilities in backend XML parsers. Impact is localized to applications that generate XML dynamically using user-provided data without sufficient secondary validation.

## Recommendation

- Upgrade to a non-vulnerable version of @xmldom/xmldom as soon as updates are available.
- Audit all `serializeToString()` call sites to ensure `requireWellFormed: true` is explicitly enabled for any serialization of untrusted or user-influenced DOM content.
- Implement strict input validation on any string used as a processing instruction target, ensuring it conforms strictly to the XML `NCName` production (no colons, whitespace, or XML-reserved characters like `>` or `?`).
- Do not rely on `requireWellFormed: true` as the sole mitigation for untrusted input, as it is an opt-in configuration that may not catch all malicious injection vectors.
