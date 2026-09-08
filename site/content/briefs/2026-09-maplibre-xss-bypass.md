---
title: MapLibre GL JS XSS Sanitizer Bypass in DOM.sanitize()
slug: 2026-09-maplibre-xss-bypass
description: An improper iteration pattern over live NamedNodeMap objects in MapLibre GL JS allows attackers to bypass XSS sanitization by injecting consecutive malicious attributes, resulting in zero-click execution when rendered.
date: "2026-09-08T21:49:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:maplibre:maplibre-gl:*:*:*:*:*:*:*:*
tags:
  - web-security
  - xss
  - javascript
vendors:
  - MapLibre
products:
  - maplibre-gl (<= 6.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can provide an HTML payload with consecutive dangerous attributes... resulting in zero-click XSS.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The second attribute survives and executes upon insertion into innerHTML.
    confidence_band: high
cves:
  - id: CVE-2026-85061
    cvss: 10
    epss: 0.00309
references:
  - https://github.com/advisories/GHSA-jrc7-96c5-q579
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85061
action_plan:
  priority: immediate_escalation
  owners:
    - Engineering
    - Security
  immediate_actions:
    - action: Upgrade maplibre-gl dependency to 6.4.1 or later.
      owner: Engineering
      due: 24h
      evidence: The issue has been resolved by creating a static snapshot of attributes... Please upgrade to 6.4.1.
  mitigation_plan:
    - priority: immediate
      action: Implement additional input validation for attribution fields.
      owner: Engineering
      addresses: CVE-2026-85061
      evidence: Sanitizing the attribute field of a source before passing it down to maplibre
---

MapLibre GL JS versions 6.4.0 and below contain a critical vulnerability in the DOM.sanitize() function within src/util/dom.ts. The function attempts to sanitize user-supplied HTML strings by iterating over the element's attributes and removing those deemed dangerous. However, the implementation incorrectly iterates over the live NamedNodeMap (elem.attributes) while simultaneously calling elem.removeAttribute() within the same loop. 

Because NamedNodeMap is a live collection, removing an attribute shifts the index of all remaining attributes. This shift causes the iterator to skip the subsequent attribute in the list, allowing malicious attributes to bypass the filter. By crafting an HTML payload with consecutive dangerous attributes (such as `<details open onload="1" ontoggle="...">`), an attacker can ensure one attribute is stripped while the next is preserved. This leads to zero-click XSS when the attribution string is subsequently injected into the application's DOM. This vulnerability affects any implementation rendering untrusted or third-party attribution strings.

## Impact

Successful exploitation allows for zero-click cross-site scripting (XSS) in the context of the application using MapLibre GL JS. This can lead to session hijacking, sensitive data theft, or arbitrary actions performed on behalf of the user. The vulnerability impacts any application that passes untrusted or user-supplied attribution strings through the map rendering engine.

## Recommendation

* Upgrade to MapLibre GL JS version 6.4.1 or later immediately to incorporate the static attribute snapshot fix.
* If upgrading is not immediately possible, implement server-side or pre-processing sanitization of attribution strings before they are passed to the map rendering component.
* Audit application code for instances where third-party or user-controlled input is passed to map attribution settings.
