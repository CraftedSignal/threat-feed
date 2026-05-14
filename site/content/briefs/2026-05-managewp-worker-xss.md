---
title: ManageWP Worker Plugin Vulnerable to Stored XSS via HTTP Header
slug: 2026-05-managewp-worker-xss
description: The ManageWP Worker plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'MWP-Key-Name' HTTP request header, allowing unauthenticated attackers to inject arbitrary web scripts that execute when an administrator visits the plugin's connection management page with debug parameters; this affects all versions up to and including 4.9.31.
date: "2026-05-14T07:17:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - cve-2026-3718
vendors:
  - WordPress
products:
  - ManageWP Worker plugin <= 4.9.31
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3718
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3718
rules:
  - title: Detect CVE-2026-3718 Exploitation — ManageWP Worker Stored XSS
    description: Detects CVE-2026-3718 exploitation — HTTP requests with a 'MWP-Key-Name' header containing Javascript code.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious MWP-Key-Name HTTP Header
    description: Detects suspicious MWP-Key-Name HTTP header in web requests, potentially indicating an attempt to exploit CVE-2026-3718.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The ManageWP Worker plugin, a WordPress extension designed for website management, is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability. This flaw, identified as CVE-2026-3718, resides within the handling of the 'MWP-Key-Name' HTTP request header. Versions up to and including 4.9.31 are affected. The vulnerability stems from inadequate input sanitization and output escaping, allowing unauthenticated attackers to inject malicious JavaScript code. The injected script executes within an administrator's browser session when they access the plugin's connection management page, especially when debug parameters are enabled, potentially leading to account compromise or further malicious actions. This vulnerability poses a significant risk to WordPress sites utilizing the ManageWP Worker plugin.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP request targeting a WordPress site using the ManageWP Worker plugin.
2.  The attacker includes the 'MWP-Key-Name' header in the HTTP request.
3.  The attacker injects a malicious JavaScript payload within the 'MWP-Key-Name' header value.
4.  The WordPress server processes the HTTP request, and the ManageWP Worker plugin stores the attacker-supplied malicious header value.
5.  An administrator logs into the WordPress dashboard and navigates to the ManageWP Worker plugin's connection management page.
6.  The plugin retrieves the stored 'MWP-Key-Name' header value.
7.  Due to insufficient output escaping, the malicious JavaScript payload is rendered within the administrator's browser.
8.  The malicious JavaScript payload executes within the administrator's browser session, potentially performing actions such as session hijacking or further administrative actions.

## Impact

Successful exploitation of this Stored XSS vulnerability (CVE-2026-3718) within the ManageWP Worker plugin can lead to a complete compromise of the affected WordPress website. An attacker can inject arbitrary JavaScript code that executes within the context of an administrator's session. This can be used to steal sensitive information, such as session cookies, modify website content, create new administrative accounts, or redirect users to malicious websites. Given the widespread usage of WordPress and the ManageWP Worker plugin, a significant number of websites are potentially vulnerable.

## Recommendation

*   Upgrade the ManageWP Worker plugin to the latest version, which addresses CVE-2026-3718 (per vendor advisory).
*   Deploy the provided Sigma rule "Detect CVE-2026-3718 Exploitation — ManageWP Worker Stored XSS" to identify exploitation attempts.
*   Monitor web server logs for HTTP requests containing the 'MWP-Key-Name' header with suspicious JavaScript payloads (see IOCs).
*   Enable output escaping for HTTP headers processed by WordPress plugins to prevent XSS vulnerabilities.
