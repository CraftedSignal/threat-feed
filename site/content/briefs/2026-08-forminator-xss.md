---
title: Stored XSS Vulnerability in Forminator Forms WordPress Plugin
slug: 2026-08-forminator-xss
description: The Forminator Forms WordPress plugin (up to v1.57.0.1) is vulnerable to unauthenticated Stored Cross-Site Scripting (XSS) via the Rich-Text Textarea field, allowing malicious script execution in the context of victim browsers.
date: "2026-08-28T07:11:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - xss
  - wordpress
vendors:
  - WPMU DEV
products:
  - Forminator Forms – Contact Form, Payment Form & Custom Form Builder (<= 1.57.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-18324
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18324
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Forminator plugin to 1.57.0.2
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to and including 1.57.0.1
  mitigation_plan:
    - priority: immediate
      action: Disable Rich-Text editor option in Forminator forms
      owner: IT Operations
      addresses: CVE-2026-18324
      evidence: Exploitation requires that the targeted Textarea field has the Rich-Text editor option enabled
---

The Forminator Forms - Contact Form, Payment Form & Custom Form Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) through its Rich-Text Textarea field component. This vulnerability, tracked as CVE-2026-18324, affects all plugin versions up to and including 1.57.0.1. The flaw stems from insufficient input sanitization and output escaping when processing content submitted through the Rich-Text editor.

Because the vulnerability is unauthenticated, an external actor can craft a payload containing arbitrary JavaScript and submit it via a public-facing form that utilizes a Rich-Text Textarea field. The payload is stored on the server and executes in the browser of any user (such as an administrator or other site visitor) who views the page containing the rendered input. This poses a significant risk for session hijacking, unauthorized actions performed on behalf of legitimate users, and potential defacement of the WordPress site. Organizations using this plugin should verify if the Rich-Text editor is enabled on any publicly accessible forms and restrict access or patch immediately to version 1.57.0.2 or later.

## Impact

The vulnerability allows unauthenticated attackers to execute arbitrary JavaScript within the context of a victim's session. In WordPress environments, this typically leads to the theft of administrative session cookies, unauthorized modification of site content, creation of new administrative accounts, or redirection of users to malicious infrastructure. The exploitability is limited to forms where the specific Rich-Text editor component is actively configured.

## Recommendation

- Update the Forminator Forms plugin to version 1.57.0.2 or later immediately to patch CVE-2026-18324.
- Audit existing WordPress forms to identify and disable the Rich-Text editor option on public-facing Textarea fields until patching is complete.
- Monitor web application firewall (WAF) logs for POST requests containing script tags or event handlers directed at endpoints used by the Forminator plugin.
