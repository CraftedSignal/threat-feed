---
title: Stored XSS in Magic Tooltips For Contact Form 7 Plugin
slug: 2026-10-xss-magic-tooltips
description: An unauthenticated Stored Cross-Site Scripting (XSS) vulnerability in Magic Tooltips For Contact Form 7 plugin up to version 1.0.34 allows attackers to inject malicious scripts via the author parameter.
date: "2026-10-03T06:53:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:magic_tooltips_for_contact_form_7:*:*:*:*:*:*:*:*
vendors:
  - WordPress
products:
  - Magic Tooltips For Contact Form 7 (<= 1.0.34)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can supply a malicious script payload, encoded as HTML entities, within the author parameter of a comment submission.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-101928
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101928
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update Magic Tooltips For Contact Form 7 to latest available version
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable up to 1.0.34
  mitigation_plan:
    - priority: immediate
      action: Disable plugin if update is unavailable
      owner: IT Operations
      addresses: CVE-2026-101928
      evidence: Vulnerability allows unauthenticated XSS
---

The Magic Tooltips For Contact Form 7 plugin for WordPress is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-101928) impacting all versions up to and including 1.0.34. The flaw stems from insufficient input sanitization and improper output escaping within the plugin's comment handling logic. Specifically, the plugin employs an 'esc_html' filter callback that inadvertently decodes HTML-entity-encoded payloads back into live HTML.

An unauthenticated attacker can supply a malicious script payload, encoded as HTML entities, within the 'author' parameter of a comment submission. This payload bypasses the standard 'sanitize_text_field' protections. Once stored, the script executes in the context of an administrator's browser when they access the 'wp-admin/edit-comments.php' page. This represents a significant risk for privilege escalation via session hijacking or administrative action manipulation within the WordPress dashboard.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator's session. This may lead to account takeover, unauthorized administrative actions, or the deployment of further malicious content within the site, potentially compromising all users and data managed by the affected WordPress instance.

## Recommendation

* Update the Magic Tooltips For Contact Form 7 plugin to a version later than 1.0.34, or disable the plugin until a patch is applied.
* Monitor web server access logs for POST requests to comment submission endpoints containing HTML entity-encoded patterns or suspicious script tags.
* Implement a Web Application Firewall (WAF) rule to block POST requests containing common XSS vectors in comment form parameters.
