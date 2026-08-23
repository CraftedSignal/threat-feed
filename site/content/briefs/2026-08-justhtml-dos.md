---
title: Denial of Service in justhtml via Uncontrolled Recursion
slug: 2026-08-justhtml-dos
description: The justhtml library version 1.9.1 and earlier is vulnerable to a denial of service attack where malicious, deeply nested HTML tags trigger a Python RecursionError during parsing.
date: "2026-08-23T17:37:42Z"
type: advisory
types:
  - advisory
severities:
  - low
products:
  - justhtml (<= 1.9.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can supply HTML for parsing can provide deeply nested elements to exceed CPython's default recursion limit.
    confidence_band: high
cves:
  - id: CVE-2026-9769
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9769
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update justhtml library to 1.10.0
      owner: Application Security
      due: 48h
      evidence: CVE-2026-9769 patched in 1.10.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade dependency
      owner: IT Operations
      addresses: CVE-2026-9769
      evidence: CVE-2026-9769
---

The justhtml library is susceptible to a denial of service (DoS) vulnerability, tracked as CVE-2026-9769, due to an uncontrolled recursion flaw in its HTML parsing logic. The vulnerability resides in the TreeBuilder.finish() function, which invokes _populate_selectedcontent() to process the DOM tree. This function initiates a recursive traversal using _find_elements() and _find_element() without implementing a depth limit. An attacker can craft a payload containing approximately 1000 deeply nested elements, such as &lt;div> tags, which consumes the stack and triggers an unhandled Python RecursionError. Depending on the architecture of the host application, this exception can result in worker crashes, request failures, or total service disruption. The issue is resolved in version 1.10.0.

## Impact

Successful exploitation results in a denial of service, potentially causing worker processes or the entire web application to terminate unexpectedly when parsing malicious user-supplied content. This vulnerability affects any application using justhtml as a parser for untrusted HTML inputs.

## Recommendation

* Update the justhtml dependency to version 1.10.0 or later immediately to incorporate the recursion depth mitigation.
* Audit applications utilizing justhtml to ensure they are not exposing the library's parsing functions to unsanitized, externally-provided HTML content.
* Implement input validation or limit the maximum payload size/depth before passing data to the justhtml parser if an immediate update is not feasible.
