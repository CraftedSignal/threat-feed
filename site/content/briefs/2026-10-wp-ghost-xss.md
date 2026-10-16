---
title: Stored Cross-Site Scripting in Hide My WP Ghost WordPress Plugin
slug: 2026-10-wp-ghost-xss
description: Unauthenticated attackers can exploit insufficient input sanitization in the Hide My WP Ghost plugin to inject persistent malicious scripts into WordPress pages.
date: "2026-10-16T06:28:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpghost:hide_my_wp_ghost:*:*:*:*:*:wordpress:*:*
vendors:
  - WP Ghost
products:
  - Hide My WP Ghost (<= 7.0.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can inject arbitrary web scripts in pages that will execute whenever a user clicks on the injected link.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute.
    confidence_band: high
cves:
  - id: CVE-2026-89051
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89051
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Hide My WP Ghost to version 7.0.13 or later
      owner: IT Operations
      due: 48h
      evidence: Source identifies 7.0.12 and earlier as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Configure WAF to inspect and block malicious script injection attempts targeting the plugin
      owner: Security Operations
      addresses: CVE-2026-89051
      evidence: Insufficient input sanitization in replaceHeadersAndTags function
---

The Hide My WP Ghost (Security & Firewall) plugin for WordPress is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability. The flaw exists within the 'replaceHeadersAndTags' function, which fails to properly sanitize user-supplied input or escape output before rendering it on the page. This vulnerability affects all versions of the plugin up to, and including, 7.0.12. An unauthenticated attacker can leverage this weakness to inject arbitrary web scripts into the site's content. When an unsuspecting user navigates to the compromised page or interacts with the injected link, the malicious script executes within the user's browser context. This can lead to session hijacking, unauthorized actions performed on behalf of the user, or redirection to malicious domains. Organizations utilizing this plugin should prioritize updating to the latest secure version once available.

## Impact

The vulnerability allows unauthenticated attackers to execute arbitrary JavaScript in the context of other users, including site administrators. Successful exploitation can result in complete account takeover, sensitive data exfiltration from the WordPress dashboard, or the injection of malicious content designed to infect site visitors. This poses a significant risk to the integrity and confidentiality of the WordPress installation and its user base.

## Recommendation

- Audit WordPress site access logs for suspicious HTTP POST requests directed toward plugin-specific endpoints.
- Implement a Web Application Firewall (WAF) to block requests containing common XSS payloads, such as script tags or event handlers, targeting known vulnerable plugin patterns.
- Upgrade the Hide My WP Ghost plugin to a version later than 7.0.12 immediately upon vendor release.
- Enforce Content Security Policy (CSP) headers to restrict the sources from which scripts can be executed, mitigating the impact of successful XSS injections.
