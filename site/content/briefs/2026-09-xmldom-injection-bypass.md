---
title: xmldom requireWellFormed Serialization Bypass
slug: 2026-09-xmldom-injection-bypass
description: The xmldom serializer fails to properly validate element and attribute names when the requireWellFormed option is enabled, allowing attackers to inject arbitrary markup via line-terminated strings.
date: "2026-09-08T21:50:46Z"
lastmod: "2026-09-08T21:51:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:xmldom_project:xmldom:0.9.11:*:*:*:*:*:*:*
tags:
  - injection
  - xss
  - library-vulnerability
vendors:
  - xmldom
products:
  - xmldom (0.9.11)
  - xmldom (0.9.0 - 0.9.11)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The malformed name is accepted into the DOM and subsequently serialized verbatim, leading to markup or structure injection, which can facilitate XSS.
    confidence_band: high
cves:
  - id: CVE-2026-83617
    epss: 0.00328
references:
  - https://github.com/advisories/GHSA-jxjr-3g7g-3944
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83617
  - https://github.com/advisories/GHSA-3px3-54cx-rmw9
  - https://nvd.nist.gov/vuln/detail/CVE-2026-83609
action_plan:
  priority: elevated
  owners:
    - Development
    - AppSec
  immediate_actions:
    - action: Upgrade xmldom to the patched version
      owner: Development
      due: 72h
      evidence: Source states xmldom v0.9.11 is vulnerable and a fix has been applied.
  mitigation_plan:
    - priority: immediate
      action: Upgrade vulnerable xmldom dependency
      owner: Development
      addresses: CVE-2026-83617
updates:
  - at: "2026-09-08T21:51:00Z"
    level: L2
    summary: added coverage for xmldom (0.9.0 - 0.9.11)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-3px3-54cx-rmw9
---

The xmldom package is vulnerable to a security bypass affecting the `requireWellFormed` option in `XMLSerializer`. The issue stems from the use of a regular expression compiled with the `m` (multiline) flag to validate XML element and attribute names. Under these conditions, the `$` anchor matches line terminators rather than the end of the entire string. Consequently, the validator only verifies that the first line of an element or attribute name is well-formed, allowing any content following a line terminator (U+000A, U+000D, U+2028, or U+2029) to be serialized verbatim.

This vulnerability impacts applications that rely on the `requireWellFormed: true` option as a defense against name-injection attacks, such as those identified in GHSA-w2rr-34g9-rvrj and GHSA-4w3w-2rp5-g8jm. Attackers capable of influencing element or attribute names during programmatic DOM construction can bypass these safety checks to inject arbitrary XML or HTML. If the resulting output is rendered in a browser, this injection can lead to Cross-Site Scripting (XSS).

## Impact

The vulnerability allows for the bypass of previously implemented security mitigations for XML name injection. Successful exploitation enables the injection of arbitrary markup into serialized XML strings. When these strings are rendered in web contexts, attackers can achieve Cross-Site Scripting (XSS), potentially leading to unauthorized data access, session hijacking, or other client-side malicious activity. This affects all downstream applications that trust `xmldom` to sanitize output through the `requireWellFormed` serializer option.

## Recommendation

- Upgrade the `xmldom` dependency to a version that patches CVE-2026-83617.
- Audit all application codebases for instances of `XMLSerializer.serializeToString()` that utilize the `{ requireWellFormed: true }` option to ensure they are updated to the corrected library version.
- For applications handling untrusted user input, implement server-side validation of element and attribute names before DOM construction to ensure they strictly conform to XML QName specifications.
- Ensure that serialized output containing user-controlled data is properly escaped or sanitized before rendering it in browser-based contexts to mitigate residual XSS risks.
