---
title: WP Editor Plugin CSRF Vulnerability
slug: 2024-01-wp-editor-csrf
description: The WP Editor plugin for WordPress is vulnerable to Cross-Site Request Forgery (CSRF) in versions up to 1.2.9.2, allowing unauthenticated attackers to overwrite arbitrary plugin and theme PHP files with malicious code by tricking a site administrator into clicking a link.
date: "2026-05-01T12:16:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csrf
  - wordpress
  - plugin
  - vulnerability
vendors:
  - WordPress
products:
  - WP Editor plugin <= 1.2.9.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-3772
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3772
rules:
  - title: Detect WP Editor Plugin CSRF Attempt
    description: Detects potential CSRF attempts targeting the WP Editor plugin by looking for requests to the 'add_plugins_page' or 'add_themes_page' functions without a valid nonce.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect WP Editor Plugin File Overwrite
    description: Detects file overwrite attempts on plugin or theme files associated with WP Editor Plugin
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The WP Editor plugin, a WordPress plugin, contains a Cross-Site Request Forgery (CSRF) vulnerability affecting versions up to and including 1.2.9.2. This vulnerability stems from a lack of nonce verification in the 'add_plugins_page' and 'add_themes_page' functions. An unauthenticated attacker can exploit this vulnerability by crafting a malicious request designed to overwrite arbitrary plugin and theme PHP files with attacker-controlled code. The success of this attack hinges on the attacker's ability to deceive a site administrator into triggering the forged request, typically by clicking a specially crafted link. This flaw allows for potential arbitrary code execution on the targeted WordPress site.

## Attack Chain

1.  The attacker identifies a vulnerable WordPress site running a WP Editor plugin version <= 1.2.9.2.
2.  The attacker crafts a malicious HTTP request targeting the 'add_plugins_page' or 'add_themes_page' functions. This request includes parameters designed to overwrite a specific plugin or theme PHP file with attacker-supplied code.
3.  The attacker social engineers a WordPress administrator into clicking a malicious link or visiting a compromised website containing the forged request. This could be achieved via phishing emails or other deceptive techniques.
4.  If the administrator is logged into the WordPress dashboard, their browser automatically sends the forged request to the vulnerable WordPress site.
5.  Due to the missing nonce verification, the WordPress site processes the request without validating its origin.
6.  The target plugin or theme PHP file is overwritten with the attacker's malicious code.
7.  The attacker's code is executed when the plugin or theme is loaded or accessed.
8.  The attacker achieves arbitrary code execution on the WordPress server, potentially leading to complete site compromise.

## Impact

Successful exploitation of this CSRF vulnerability allows an unauthenticated attacker to inject arbitrary PHP code into a WordPress website. This can lead to a full compromise of the website, including data theft, defacement, or the installation of backdoors for persistent access. Given the widespread use of WordPress and the WP Editor plugin, a large number of websites are potentially at risk. Successful attacks can result in significant reputational damage and financial losses for affected website owners.

## Recommendation

*   Upgrade the WP Editor plugin to the latest available version, which includes a fix for CVE-2026-3772.
*   Implement strong CSRF protection measures on all WordPress forms and administrative functions.
*   Deploy the provided Sigma rule to detect attempts to exploit this vulnerability through suspicious requests to the `add_plugins_page` or `add_themes_page` endpoints.
