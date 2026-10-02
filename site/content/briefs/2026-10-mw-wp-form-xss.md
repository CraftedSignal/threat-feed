---
title: Stored XSS in MW WP Form WordPress Plugin via post_id Parameter
slug: 2026-10-mw-wp-form-xss
description: The MW WP Form WordPress plugin is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient sanitization of the 'post_id' parameter, enabling unauthenticated attackers to bypass CSRF protections and execute arbitrary scripts in victim sessions.
date: "2026-10-02T10:23:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mw_wp_form_project:mw_wp_form:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-96567
vendors:
  - WordPress
products:
  - MW WP Form (<= 5.1.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505.003
    technique_name: Server Software Component
    evidence: The CSRF gate protecting form submission (MW_WP_Form_Csrf) is bypassable by any unauthenticated visitor who first loads the public form page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96567
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96567
rules:
  - title: Detect CVE-2026-96567 Exploitation - POST Request with Script Injection
    description: Detects exploitation of CVE-2026-96567 by identifying suspicious XSS payloads within the post_id parameter during a POST request.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch MW WP Form to a version > 5.1.7
      owner: IT Operations
      due: 24h
      evidence: Source states vulnerability exists in all versions up to 5.1.7
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rule to block script injection in post_id parameter
      owner: SOC
      addresses: CVE-2026-96567
      evidence: NVD vulnerability report
---

The MW WP Form plugin for WordPress, in versions 5.1.7 and earlier, contains a critical input sanitization vulnerability. Attackers can leverage this flaw to perform Stored Cross-Site Scripting (XSS) by manipulating the 'post_id' parameter during form processing. The vulnerability is compounded by an insecure CSRF protection mechanism (MW_WP_Form_Csrf), which relies on a double-submit cookie that can be acquired by any unauthenticated visitor who loads the public-facing form page. Because the plugin fails to properly sanitize input or escape output, malicious actors can inject arbitrary JavaScript payloads into the WordPress database. These payloads execute in the browsers of users - including administrators - who view the affected pages or form submissions, potentially leading to unauthorized actions, session hijacking, or site defacement. This issue highlights the danger of predictable or bypassable CSRF tokens when combined with inadequate input handling.

## Attack Chain

1. Attacker loads a public webpage containing a form managed by the MW WP Form plugin.
2. The application serves the form and issues a double-submit CSRF cookie (MW_WP_Form_Csrf) to the browser.
3. The attacker retrieves the valid CSRF token/cookie pair from the initial page load.
4. The attacker crafts a malicious HTTP POST request targeting the form submission endpoint.
5. The attacker includes a cross-site scripting payload within the 'post_id' parameter.
6. The application accepts the POST request, validating the CSRF cookie, and saves the malicious 'post_id' to the underlying database without sanitization.
7. A victim user, such as an administrator, accesses the administrative interface or a page displaying the form submission data.
8. The stored JavaScript payload executes in the victim's browser context, enabling further malicious activity.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of any user who accesses the compromised form submission pages. This may result in total site compromise if an administrative account views the malicious payload, enabling account takeover, unauthorized creation of admin users, or malicious modifications to site content.

## Recommendation

Prioritized actions for security operations and IT teams:
- Immediately identify all WordPress instances running MW WP Form versions 5.1.7 or older.
- Update the MW WP Form plugin to the latest secure version addressing CVE-2026-96567.
- Implement a Web Application Firewall (WAF) rule to block POST requests containing suspicious characters (e.g., &lt;script>, javascript:, onload=) in the 'post_id' parameter.
- Monitor webserver access logs for anomalous POST requests to form submission endpoints originating from unknown or non-customer IP addresses.
