---
title: CVE-2026-104021 Code Injection in Fastcache WordPress Plugin
slug: 2026-10-fastcache-code-injection
description: An authenticated administrator can exploit CVE-2026-104021 in the Fastcache plugin for WordPress to inject arbitrary Apache directives into the .htaccess file, leading to remote code execution.
date: "2026-10-10T05:34:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:host.it:fastcache:*:*:*:*:*:wordpress:*:*
vendors:
  - Host.it
products:
  - Fastcache (<= 1.7.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Fastcache by Host.it plugin for WordPress is vulnerable to Code Injection... via the fastcache_settings[cache_cookie_exclude][] parameter.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: enabling server-level configuration changes such as setting php_value auto_prepend_file to execute attacker-controlled PHP code
    confidence_band: high
cves:
  - id: CVE-2026-104021
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104021
rules:
  - title: Detect CVE-2026-104021 Exploitation - Apache Directive Injection in .htaccess
    description: Detects exploitation of CVE-2026-104021 by identifying HTTP POST requests to WordPress containing shell-related directives in the Fastcache settings parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit WordPress installations for Fastcache plugin version 1.7.4 or lower
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability affects all versions up to and including 1.7.4
  mitigation_plan:
    - priority: immediate
      action: Upgrade Fastcache to the latest available patched version
      owner: IT Operations
      addresses: CVE-2026-104021
      evidence: Plugin is vulnerable in 1.7.4 and lower
---

CVE-2026-104021 is a critical code injection vulnerability affecting the Fastcache by Host.it plugin for WordPress, specifically in all versions up to and including 1.7.4. The vulnerability arises because the plugin registers the `cache_cookie_exclude` setting without implementing a necessary `sanitize_callback`. When the plugin builds site `.htaccess` rules via the `buildSiteHtaccessRules()` function, it only applies `trim()` to cookie values. This normalization fails to remove newline characters, allowing an authenticated administrator to inject arbitrary Apache directives. By crafting malicious input into the `fastcache_settings[cache_cookie_exclude][]` parameter, an attacker can break out of the intended capture group and append directives such as `php_value auto_prepend_file` to the `.htaccess` file. This allows for server-level configuration changes and the execution of arbitrary PHP code on every request processed by the web server.

## Impact

Successful exploitation of this vulnerability allows an authenticated administrator to achieve remote code execution (RCE) on the underlying server. Since the vulnerability involves modifying the `.htaccess` file, the attacker gains the ability to manipulate server-level configurations, potentially leading to full site compromise and persistence. Organizations running WordPress with the Fastcache plugin version 1.7.4 or lower are at risk.

## Recommendation

Prioritized actions for security and IT teams:
- Immediately update the Fastcache plugin to the latest version once a patch is released to resolve the sanitization logic in `buildSiteHtaccessRules()`.
- Monitor web server access logs for requests targeting `wp-admin` that include suspicious `fastcache_settings` parameters.
- Audit the contents of `.htaccess` files on affected WordPress instances for unauthorized entries, specifically looking for `php_value` or `php_flag` directives that were not manually configured.
- Restrict administrative access to the WordPress dashboard to trusted IP addresses to mitigate the impact of this vulnerability, as exploitation requires authenticated administrator privileges.
