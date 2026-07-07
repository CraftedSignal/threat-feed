---
title: WordPress WPZOOM Portfolio Plugin XSS Vulnerability (CVE-2026-49069)
slug: 2026-07-wpzoom-portfolio-xss
description: A critical reflected cross-site scripting (XSS) vulnerability, CVE-2026-49069, affects the WPZOOM Portfolio plugin (version 1.4.21 and earlier) for WordPress, enabling unauthenticated attackers to inject malicious JavaScript into web pages via the `wpzoom_load_more_items` AJAX action, leading to client-side script execution in victims' browsers.
date: "2026-07-06T13:23:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - wordpress
  - webapps
  - cve
vendors:
  - WPZOOM
  - WordPress
products:
  - WordPress Plugin WPZOOM Portfolio <= 1.4.21
  - WordPress 6.x
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public webapps exploit has been published on Exploit-DB for WordPress Plugin WPZOOM Portfolio 1.4.21, demonstrating a Reflected Cross-Site Scripting (XSS) vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can break out of the HTML attribute string and inject arbitrary attributes, including malicious JavaScript event handlers. The payload executes when the underlying query returns at least one published portfolio item.
    confidence_band: high
cves:
  - id: CVE-2026-49069
    cvss: 7.1
    epss: 0.00142
references:
  - https://www.exploit-db.com/exploits/52611
  - https://wpzoom.com
  - https://wordpress.org
iocs:
  - type: domain
    value: wpzoom.com
  - type: domain
    value: wordpress.org
ioc_counts:
  domain: 2
rules:
  - title: Detect WordPress WPZOOM Portfolio XSS Exploitation (CVE-2026-49069)
    description: Detects CVE-2026-49069 exploitation in WordPress WPZOOM Portfolio plugin via specific XSS payload in wpzoom_load_more_items AJAX action. This reflected XSS uses single quotes to break out of HTML attributes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
---

A publicly available exploit has been published on Exploit-DB detailing a reflected Cross-Site Scripting (XSS) vulnerability, CVE-2026-49069, affecting the WordPress Plugin WPZOOM Portfolio, specifically versions up to and including 1.4.21. This flaw resides within the `wpzoom_load_more_items` AJAX action, which is accessible to unauthenticated users without proper nonce validation or privilege checks. Attackers can exploit this by crafting a malicious POST request that injects arbitrary JavaScript into the `posts_data` parameter's `class` key. Although `sanitize_text_field()` strips angle brackets, it fails to sanitize single quotes, allowing an attacker to break out of HTML attribute contexts and inject event handlers like `onmouseover`. The presence of a working Proof of Concept (PoC) significantly increases the immediate risk to organizations using vulnerable versions of this plugin.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP POST request.
2.  The request targets the `/wp-admin/admin-ajax.php` endpoint on the vulnerable WordPress site.
3.  The POST request body includes `action=wpzoom_load_more_items` and a `posts_data` parameter containing the XSS payload: `{"source":"post","class":"x' onmouseover='alert(document.domain)' y='"}`.
4.  The server processes the `wpzoom_load_more_items` AJAX action; `sanitize_text_field()` is applied to `posts_data`, stripping angle brackets but preserving single quotes.
5.  The attacker-controlled `class` value is subsequently concatenated directly into single-quoted HTML attributes within the `items_html()` function without context-aware output escaping (e.g., `<li class='{$class}_item ...'>`).
6.  The server's response includes the crafted HTML, such as `<li class='x' onmouseover='alert(document.domain)' y='_item ...'>`, which is then rendered in a victim's browser.
7.  When a victim's browser renders the affected page and the victim interacts with the vulnerable element (e.g., hovering over the loaded portfolio item), the injected `onmouseover` JavaScript event handler executes.
8.  The attacker achieves client-side script execution, potentially leading to session hijacking, defacement, or redirection to malicious sites.

## Impact

The successful exploitation of CVE-2026-49069 can lead to various client-side attacks, including session hijacking, defacement of the affected WordPress site, redirection of users to malicious websites, or the delivery of further malware. Since the vulnerability is unauthenticated and widely affects WordPress installations using the WPZOOM Portfolio plugin up to version 1.4.21, any user browsing the compromised site could become a victim. Organizations using this plugin could face reputation damage, data breaches, and significant operational disruption if their sites are exploited.

## Recommendation

*   **Patch immediately:** Upgrade the WPZOOM Portfolio plugin to a version greater than 1.4.21 to remediate CVE-2026-49069.
*   **Deploy the Sigma rule:** Deploy the `Detect WordPress WPZOOM Portfolio XSS Exploitation (CVE-2026-49069)` Sigma rule provided in this brief to your SIEM and tune for your environment to detect exploitation attempts.
*   **Monitor web server logs:** Regularly review web server access logs for suspicious POST requests to `/wp-admin/admin-ajax.php` containing unusual `posts_data` parameters, as outlined in the provided IOCs.
