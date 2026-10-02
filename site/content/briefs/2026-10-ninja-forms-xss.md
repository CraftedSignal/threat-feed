---
title: Stored XSS in Ninja Forms WordPress Plugin
slug: 2026-10-ninja-forms-xss
description: The Ninja Forms WordPress plugin versions 3.15.4 and earlier contain a stored Cross-Site Scripting vulnerability allowing unauthenticated attackers to inject malicious scripts via Paragraph Text fields with Rich Text Editor enabled.
date: "2026-10-02T06:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ninjaforms:ninja_forms:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - xss
  - cve-2026-90438
vendors:
  - Ninja Forms
products:
  - Ninja Forms – The Contact Form Builder That Grows With You (<= 3.15.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-90438
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90438
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Web Security
  immediate_actions:
    - action: Update Ninja Forms plugin to the latest version beyond 3.15.4
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-90438 mitigation
  mitigation_plan:
    - priority: immediate
      action: Disable Rich Text Editor (RTE) on Paragraph Text fields until plugin update is applied
      owner: Web Security
      addresses: CVE-2026-90438
      evidence: Vulnerability is only exploitable when RTE is enabled
---

The Ninja Forms - The Contact Form Builder That Grows With You plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization and output escaping within its Paragraph Text field handling. This vulnerability, identified as CVE-2026-90438, affects all versions up to and including 3.15.4. Unauthenticated attackers can exploit this by submitting specially crafted malicious scripts through forms where the Paragraph Text field has the Rich Text Editor (RTE) option enabled. Once submitted, the malicious payload is stored by the application and executes in the browser context of any user, such as an administrator, who views the submitted form data in the WordPress dashboard. This allows for session hijacking, credential theft, or unauthorized administrative actions.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of the WordPress administrative session. This can lead to full site compromise, unauthorized configuration changes, or the injection of further malicious content, directly impacting the security posture of any WordPress site utilizing the affected versions of the plugin.

## Recommendation

Update the Ninja Forms - The Contact Form Builder That Grows With You plugin to the latest version immediately to remediate CVE-2026-90438. Prioritize identifying and auditing any forms currently using the Paragraph Text field with the Rich Text Editor (RTE) option enabled to check for potential existing payloads.
