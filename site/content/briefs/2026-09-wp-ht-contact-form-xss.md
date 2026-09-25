---
title: Stored DOM-Based XSS in HT Contact Form WordPress Plugin
slug: 2026-09-wp-ht-contact-form-xss
description: An unauthenticated stored DOM-based cross-site scripting vulnerability in the HT Contact Form plugin for WordPress allows attackers to execute arbitrary scripts via crafted draft resume URLs.
date: "2026-09-25T08:55:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:ht_contact_form_drag_drop_form_builder_for_wordpress:*:*:*:*:*:*:*:*
tags:
  - web-application
  - wordpress
  - xss
vendors:
  - WordPress
products:
  - HT Contact Form – Drag & Drop Form Builder for WordPress (<= 2.10.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Exploitation requires tricking a user into clicking an attacker-supplied draft resume URL.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-93303
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93303
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade HT Contact Form plugin to version > 2.10.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-93303 affects versions up to 2.10.1.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to latest plugin version
      owner: IT Operations
      addresses: CVE-2026-93303
      evidence: Source states all versions up to and including 2.10.1 are vulnerable.
---

The HT Contact Form - Drag & Drop Form Builder for WordPress plugin is vulnerable to a stored DOM-based cross-site scripting (XSS) vulnerability (CVE-2026-93303) affecting all versions up to and including 2.10.1. The flaw resides in the 'form_data' Rich Text Field, specifically within the draft save and resume functionality. Insufficient input sanitization and output escaping allow unauthenticated attackers to inject malicious scripts into saved form drafts. To exploit this, an attacker must trick an authenticated user into interacting with a crafted URL containing a valid 'draft_key' and 'access_token', which the attacker can retrieve from the plugin's response. Successful execution occurs in the context of the victim's browser session, potentially allowing unauthorized actions or session hijacking.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an administrator or user accessing the injected form page. This could result in unauthorized administrative actions, sensitive data exfiltration, or the creation of new administrative accounts within the WordPress instance.

## Recommendation

1. Patch immediately by upgrading the HT Contact Form - Drag & Drop Form Builder for WordPress plugin to a version greater than 2.10.1.
2. Audit WordPress site logs for anomalous POST requests to the plugin's draft save endpoints if unauthorized modifications are suspected.
3. Implement a strict Content Security Policy (CSP) to mitigate the impact of potential XSS attacks by restricting the sources of executable scripts.
