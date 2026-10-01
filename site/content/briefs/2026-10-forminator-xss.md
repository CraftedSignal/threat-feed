---
title: Stored Cross-Site Scripting in Forminator Forms WordPress Plugin
slug: 2026-10-forminator-xss
description: The Forminator Forms WordPress plugin is vulnerable to Stored Cross-Site Scripting via the Rich-Text Textarea field, allowing unauthenticated attackers to execute arbitrary scripts in an administrator's session.
date: "2026-10-01T10:39:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:wordpress:forminator_forms_contact_form_payment_form_custom_form_builder:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - Forminator Forms – Contact Form, Payment Form & Custom Form Builder (<= 1.57.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Successful exploitation requires an administrator to open the stored submission entry... at which point WordPress core's jQuery-based click handler... evaluates the entity-decoded href as HTML, firing the attacker's payload.
    confidence_band: high
cves:
  - id: CVE-2026-85235
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85235
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Forminator Forms to version > 1.57.2
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85235 disclosure
  mitigation_plan:
    - priority: immediate
      action: Disable Rich-Text Textarea fields in Forminator settings
      owner: IT Operations
      addresses: CVE-2026-85235
      evidence: Mitigation for lack of input sanitization in Forminator Rich-Text field
---

Forminator Forms - Contact Form, Payment Form & Custom Form Builder for WordPress (all versions up to and including 1.57.2) contains a Stored Cross-Site Scripting (XSS) vulnerability. The flaw exists within the Rich-Text Textarea field due to insufficient input sanitization and output escaping. Unauthenticated attackers can submit malicious payloads through forms that store these scripts on the backend. The payload is triggered when a WordPress administrator views the submitted entry within the 'Forminator Entries' dashboard view. Upon interaction with a specific UI element, the WordPress core's jQuery-based click handler on the '.contextual-help-tabs a' element incorrectly processes the injected content, leading to script execution within the authenticated administrator's session context. This vulnerability can lead to unauthorized administrative actions, such as account creation or plugin configuration changes.

## Attack Chain

1. Attacker identifies a public-facing form created via the Forminator Forms plugin.
2. Attacker submits a form entry containing a malicious XSS payload within the Rich-Text Textarea field.
3. The malicious script is saved to the WordPress database as part of the form submission.
4. An administrator logs into the WordPress dashboard (`/wp-admin`).
5. The administrator navigates to the 'Forminator Entries' section to review submitted data.
6. The attacker's payload is rendered on the page, and the administrator interacts with the UI element linked to the vulnerable jQuery handler.
7. The browser executes the injected payload within the context of the administrator's authenticated session.
8. The attacker achieves full control or performs unauthorized administrative actions via the compromised session.

## Impact

Successful exploitation allows unauthenticated attackers to gain administrative privileges on a WordPress site by executing malicious JavaScript in an active administrator session. This could result in unauthorized account creation, modifications to site settings, or the deployment of additional malicious plugins, impacting the integrity and availability of the affected WordPress instance.

## Recommendation

1. Upgrade Forminator Forms - Contact Form, Payment Form & Custom Form Builder to a version beyond 1.57.2 immediately upon release of a security patch.
2. Disable the Rich-Text Textarea field in form configurations as a temporary mitigation until the patch is applied.
3. Implement Content Security Policy (CSP) headers to restrict the execution of inline scripts and unauthorized external domains.
4. Use web application firewalls (WAF) to inspect form submissions for common XSS patterns, specifically targeting HTML tags and event handlers in input fields.
