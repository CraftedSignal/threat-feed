---
brief_id: brief-2026-11-04-slim-jetpack-xss
event_id: brief-2026-11-04-slim-jetpack-xss
revision: 1
activity_at: "2026-11-04T10:42:22Z"
title: 'Slim Jetpack: Stored Cross-Site Scripting via contact form (CVE-2026-115498)'
slug: 2026-11-slim-jetpack-xss
description: The Slim Jetpack WordPress plugin is vulnerable to unauthenticated Stored Cross-Site Scripting (XSS) via the website contact-field parameter, enabling attackers to inject arbitrary web scripts through the [contact-form] shortcode.
date: "2026-11-04T10:42:22Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-confirmed vulnerability details; no specific exploit telemetry provided for Sigma rule generation.
cpes:
  - cpe:2.3:a:slim_jetpack_project:slim_jetpack:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
  - plugin-vulnerability
products:
  - Slim Jetpack (<= 2.7.0.1)
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
    technique_name: JavaScript
    evidence: The Slim Jetpack plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ... parameter ... allowing unauthenticated visitors to store payloads.
    confidence_band: high
cves:
  - id: CVE-2026-115498
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115498
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Slim Jetpack plugin to version > 2.7.0.1
      owner: IT Operations
      due: 24h
      evidence: Vulnerable in all versions up to, and including, 2.7.0.1
  hunt_leads:
    - lead: Identify unauthenticated POST requests to the [contact-form] shortcode containing suspicious characters
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-method, cs-uri-stem, cs-uri-query)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The nonce and authentication checks on form submission are only enforced for logged-in users, allowing unauthenticated visitors to store payloads via any page containing the [contact-form] shortcode.
  mitigation_plan:
    - priority: immediate
      action: Apply WAF filter for POST requests containing script tags in form parameters
      owner: SOC
      addresses: CVE-2026-115498
      evidence: vulnerable to Stored Cross-Site Scripting via the g<PAGE_ID>-website parameter
---

The Slim Jetpack plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization and output escaping. The vulnerability resides in the 'g&lt;PAGE_ID>-website' parameter. Unauthenticated attackers can exploit this via the [contact-form] shortcode because nonce and authentication checks are only enforced for authenticated users, allowing guest submissions of malicious payloads.

## Impact
Successful exploitation allows unauthenticated attackers to inject arbitrary web scripts. These scripts execute in the browser of any user who accesses the page where the payload is stored.

## Recommendation
- Update the Slim Jetpack plugin to a version beyond 2.7.0.1 immediately.
- Implement a Web Application Firewall (WAF) rule to inspect POST requests to the [contact-form] shortcode endpoints for script tags or common XSS patterns in the website URL/contact fields.
- Review WordPress access logs for anomalous POST requests containing HTML or script tags directed at pages utilizing the Slim Jetpack [contact-form].
