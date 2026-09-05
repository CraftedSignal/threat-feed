---
title: Stored Cross-Site Scripting in WordPress QuickCal Plugin
slug: 2026-09-quickcal-xss
description: The QuickCal WordPress plugin is vulnerable to unauthenticated Stored Cross-Site Scripting (XSS) via custom field parameters, allowing attackers to execute arbitrary scripts in the context of site users.
date: "2026-09-05T07:30:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:quickcal:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - xss
  - cve-2026-15984
vendors:
  - WordPress
products:
  - QuickCal (<= 1.0.20)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-15984
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15984
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade QuickCal plugin to version > 1.0.20
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15984
  mitigation_plan:
    - priority: immediate
      action: Remove calendar shortcode from pages if update cannot be applied
      owner: IT Operations
      addresses: CVE-2026-15984
      evidence: Nonce availability makes exploitation trivial
---

The QuickCal plugin for WordPress, in versions up to and including 1.0.20, contains a security vulnerability (CVE-2026-15984) resulting from insufficient input sanitization and output escaping. This flaw allows unauthenticated attackers to perform Stored Cross-Site Scripting (XSS) attacks by injecting arbitrary web scripts through custom field parameters. The vulnerability is exacerbated by the improper exposure of a security nonce used to protect the booked_add_appt AJAX action. This nonce is publicly embedded within the HTML source of any page utilizing the booking calendar shortcode. Because the nonce is easily retrievable by unauthenticated actors, they can successfully perform unauthorized actions and store malicious scripts that execute whenever a victim views the affected page.

## Impact

Successful exploitation of this vulnerability permits unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's session. This may lead to unauthorized data access, session hijacking, or the defacement of the affected WordPress site. Given the plugin's purpose, high-traffic booking pages are at particular risk, potentially exposing administrators and customers to credential theft or redirection to malicious sites.

## Recommendation

* Immediately update the QuickCal plugin to the latest version (patch for 1.0.20 or later) as provided by the developer.
* If an update is not immediately available, disable the booking calendar shortcode on all public-facing pages to prevent the leakage of the booked_add_appt AJAX nonce.
* Audit web server logs for suspicious HTTP POST requests directed to the booked_add_appt AJAX endpoint.
* Implement a robust Content Security Policy (CSP) that restricts script execution to trusted domains, mitigating the impact of potential XSS injections.
