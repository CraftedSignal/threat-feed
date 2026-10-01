---
title: Stored Cross-Site Scripting in Forminator Forms WordPress Plugin
slug: 2026-10-forminator-xss
description: The Forminator Forms plugin for WordPress is vulnerable to Stored XSS via the 'postdata-1[post-custom]' parameter in versions 1.57.2 and below, allowing unauthenticated attackers to execute arbitrary scripts.
date: "2026-10-01T10:40:46Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpmu_dev:forminator_forms:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - stored-xss
  - wordpress
  - cve-2026-92144
vendors:
  - WPMU DEV
products:
  - Forminator Forms (<= 1.57.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-92144
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92144
rules:
  - title: Detect CVE-2026-92144 Exploitation - Stored XSS in Forminator Forms
    description: Detects exploitation attempts targeting CVE-2026-92144 where a user submits a POST request to Forminator endpoints containing HTML script tags or event handlers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review logs for requests containing script tags toward form submission endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-92144 exploitation path
  mitigation_plan:
    - priority: immediate
      action: Upgrade Forminator Forms to the first patched version released after 1.57.2
      owner: IT Operations
      addresses: CVE-2026-92144
      evidence: Source advisory
---

The Forminator Forms - Contact Form, Payment Form & Custom Form Builder plugin for WordPress is affected by a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-92144. All versions up to and including 1.57.2 are impacted due to insufficient input sanitization and output escaping on the 'postdata-1[post-custom]' parameter. The vulnerability allows unauthenticated attackers to inject arbitrary web scripts into form submissions, which are subsequently stored and executed when a user or administrator views the page containing the injected content. The attack is highly accessible because the form submission nonce, typically a security barrier, is exposed to unauthenticated users via the publicly accessible 'wp_ajax_nopriv_forminator_get_nonce' endpoint. Successful exploitation results in the execution of unauthorized JavaScript in the context of the victim's session, potentially leading to session hijacking, defacement, or administrative action performance.

## Impact

The vulnerability poses a significant risk to WordPress sites utilizing the Forminator plugin. Successful exploitation allows unauthenticated attackers to execute malicious scripts in the browsers of users or administrators viewing the site. This could lead to account takeover, unauthorized data access, or the redirection of site traffic to malicious domains. Given the plugin's broad utility in contact and payment forms, high-traffic sites may be particularly attractive targets.

## Recommendation

Prioritized actions for security teams:
- Update the Forminator Forms plugin to a version released after 1.57.2 immediately upon availability of a patch.
- Monitor web server logs for requests to 'wp_ajax_nopriv_forminator_get_nonce' followed by POST requests to the plugin's submission endpoints containing script tags or abnormal characters in the 'postdata-1[post-custom]' parameter.
- Deploy WAF rules to sanitize or block POST requests containing HTML tags or script-related keywords ('&lt;script>', 'onload=', 'onerror=') directed toward Forminator submission endpoints.
