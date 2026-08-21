---
title: Stored XSS in WPForms Pro Plugin
slug: 2026-08-wpforms-xss
description: WPForms Pro versions up to 2.0.0.2 are vulnerable to unauthenticated Stored Cross-Site Scripting via improper input sanitization in text fields.
date: "2026-08-21T05:22:11Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WPForms
products:
  - WPForms Pro
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: 'allowing a javascript: URI stored in data-src to survive kses processing and subsequently be promoted to a live src attribute'
    confidence_band: high
cves:
  - id: CVE-2026-18409
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18409
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update WPForms Pro to a version beyond 2.0.0.2
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions 2.0.0.2 and earlier.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin
      owner: IT Operations
      addresses: CVE-2026-18409
      evidence: NVD vulnerability details
---

WPForms Pro, a widely used WordPress form-building plugin, contains a critical Stored Cross-Site Scripting (XSS) vulnerability in versions 2.0.0.2 and earlier. The flaw exists due to insufficient input sanitization and output escaping within the Single Line Text and Paragraph Text fields. An unauthenticated attacker can exploit this by submitting specially crafted input containing iframe elements. 

The vulnerability is specifically enabled by the plugin's modification of the `wp_kses_allowed_html` filter. This modification widens the allowlist to permit `iframe` elements with a `data-src` attribute. Since `data-src` is not subject to standard WordPress URI-attribute sanitization, an attacker can store a `javascript:` URI. When a site administrator views the entry via the bundled `view-entry.min.js` script, the application promotes the `data-src` attribute to a live `src` attribute, resulting in the execution of arbitrary JavaScript in the context of the administrator's session.

## Impact

Successful exploitation allows an unauthenticated attacker to inject malicious scripts into WordPress site entries. When an administrator views these entries, the script executes, potentially leading to unauthorized administrative actions, account takeover, or the exfiltration of sensitive site data. Given the ubiquity of form plugins, this affects a broad range of WordPress-powered websites.

## Recommendation

- Update WPForms Pro to a version beyond 2.0.0.2 immediately to receive the corrected sanitization logic.
- Review administrative access logs for unusual patterns or activity originating from the plugin's entry view interface.
- Audit existing form entries for anomalous iframe or script tags if the plugin cannot be updated immediately.
