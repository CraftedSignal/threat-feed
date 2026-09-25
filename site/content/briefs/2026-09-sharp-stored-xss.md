---
title: Stored XSS Vulnerability in Code16 Sharp via iframe srcdoc Attribute
slug: 2026-09-sharp-stored-xss
description: A stored XSS vulnerability in the Code16 Sharp rich text editor allows authenticated attackers to execute arbitrary JavaScript by exploiting browser-side HTML entity decoding within the iframe srcdoc attribute.
date: "2026-09-25T20:06:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:code16:sharp:*:*:*:*:*:*:*:*
vendors:
  - Code16
products:
  - Sharp (< 9.22.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with permissions to edit an Editor field can inject malicious scripts to target other users viewing the content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: Any encoded JavaScript inside a srcdoc attribute is evaluated and executed as live HTML/JS in the context of the iframe when the page is rendered.
    confidence_band: high
cves:
  - id: CVE-2026-61823
    cvss: 7.3
references:
  - https://github.com/advisories/GHSA-qxg3-46rw-79j8
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61823
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Code16 Sharp to version 9.22.5.
      owner: IT Operations
      due: 48h
      evidence: The vulnerability has been patched in version v9.22.5.
  mitigation_plan:
    - priority: immediate
      action: Manually sanitize Editor field content to strip srcdoc attributes.
      owner: Security Engineering
      addresses: CVE-2026-61823
      evidence: Users who cannot upgrade immediately can manually sanitize all content of editor fields to strip srcdoc attributes.
---

Code16 Sharp versions prior to v9.22.5 are vulnerable to a Stored Cross-Site Scripting (XSS) attack originating from improper sanitization of the `srcdoc` attribute on `<iframe>` elements within the rich text editor. While the application utilizes the Symfony HtmlSanitizer to encode special characters, the HTML specification forces browsers to decode these HTML entities when processing the `srcdoc` attribute. This behavior effectively nullifies the existing sanitization, allowing attackers to inject and execute arbitrary JavaScript. An attacker with access to the Editor field can exploit this to perform session hijacking, unauthorized account actions, or data theft against other users, including administrative accounts. The vendor has addressed this in version v9.22.5 by explicitly removing `srcdoc` from the list of allowed iframe attributes in the sanitization logic.

## Impact

The vulnerability allows authenticated attackers to perform actions on behalf of other users, including high-privileged administrators. Successful exploitation can lead to full session takeover, persistent unauthorized data access, and potential lateral movement within the administrative dashboard.

## Recommendation

* Upgrade to Code16 Sharp v9.22.5 or later to apply the patch that removes support for the srcdoc attribute in iframe elements.
* For environments unable to upgrade immediately, manually audit and sanitize all content within Editor fields to strip the srcdoc attribute from iframe tags.
* Implement strict Content Security Policy (CSP) headers that prevent the execution of inline scripts and restrict iframe sources to trusted domains.
