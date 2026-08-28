---
title: Stored Cross-Site Scripting in Optimole WordPress Plugin
slug: 2026-08-optimole-xss
description: The Optimole WordPress plugin is vulnerable to stored cross-site scripting due to improper sanitization of the above_fold_images parameter, allowing unauthenticated attackers to execute arbitrary JavaScript in victim browsers.
date: "2026-08-28T07:12:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-77365
vendors:
  - Optimole
products:
  - Optimole – Optimize Images
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The Optimole WordPress plugin is vulnerable to Stored Cross-Site Scripting via the 'a' (above_fold_images) parameter.
    confidence_band: high
cves:
  - id: CVE-2026-77365
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77365
rules:
  - title: Detect CVE-2026-77365 Exploitation - Stored XSS via Optimole Parameter
    description: Detects exploitation attempts against the Optimole plugin where the 'a' parameter contains common XSS attack patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Optimole plugin to version > 4.2.10
      owner: IT Operations
      due: 48h
      evidence: Plugin vulnerable in all versions up to, and including, 4.2.10.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF filter for 'a' parameter
      owner: IT Operations
      addresses: CVE-2026-77365
      evidence: Insufficient input sanitization in 'a' parameter.
---

The Optimole - Optimize Images plugin for WordPress (all versions up to and including 4.2.10) contains a critical security flaw involving insufficient input sanitization and output escaping. Specifically, the 'a' (above_fold_images) parameter fails to properly sanitize user-supplied input. This flaw allows an unauthenticated attacker to inject malicious JavaScript payloads into affected WordPress pages. When a user, such as a site administrator or privileged user, accesses the compromised page, the injected script executes within the context of their session. This vulnerability poses a significant risk for session hijacking, unauthorized administrative actions, or the redirection of site visitors to malicious domains. Organizations utilizing this plugin should upgrade to a patched version immediately upon availability or implement web application firewall rules to block suspicious input in the specified parameter.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary scripts in the browsers of users viewing the affected pages. This can lead to the theft of session cookies, account takeover of authenticated administrators, or the injection of malicious content into the site, damaging site integrity and potentially leading to further compromise of site visitors.

## Recommendation

* Upgrade the Optimole plugin to the latest version, ensuring all security patches are applied.
* Monitor web server access logs for HTTP requests containing suspicious script tags or JavaScript event handlers within the 'a' query parameter or request body associated with the plugin.
* Deploy WAF rules to validate input for the 'a' parameter, ensuring it adheres to expected data types and blocking payloads containing characters typical of XSS (e.g., &lt;script>, javascript:, onload=).
