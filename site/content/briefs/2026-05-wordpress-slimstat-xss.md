---
title: WordPress SlimStat Analytics Plugin Stored XSS Vulnerability (CVE-2026-7634)
slug: 2026-05-wordpress-slimstat-xss
description: The SlimStat Analytics plugin for WordPress is vulnerable to stored cross-site scripting (XSS) via the User-Agent header, allowing unauthenticated attackers to inject arbitrary web scripts if the 'show_complete_user_agent_tooltip' setting is enabled.
date: "2026-05-28T08:19:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - xss
  - wordpress
vendors:
  - WordPress
products:
  - SlimStat Analytics plugin <= 5.4.11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7634
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7634
rules:
  - title: Detect SlimStat User-Agent Header XSS Attempt
    description: Detects CVE-2026-7634 exploitation — attempts to inject XSS payloads into the User-Agent header targeting the SlimStat Analytics plugin for WordPress.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SlimStat User-Agent in URI
    description: Detects CVE-2026-7634 exploitation — User-Agent strings in URI parameters can be used to inject malicious code
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

The SlimStat Analytics plugin for WordPress is susceptible to a stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-7634. This flaw resides in versions up to and including 5.4.11. It stems from inadequate input sanitization and output escaping applied to the 'User-Agent' header. An unauthenticated attacker can exploit this vulnerability to inject malicious web scripts into pages. For the injected script to execute, the 'show_complete_user_agent_tooltip' setting must be explicitly enabled within the plugin's configuration by an administrator; this setting is disabled by default. The successful exploitation of this vulnerability allows attackers to execute arbitrary JavaScript code in the context of a user's browser when they access a page containing the injected payload.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP request with a User-Agent header containing a JavaScript payload.
2.  The attacker sends the HTTP request to a WordPress site running the vulnerable SlimStat Analytics plugin.
3.  The SlimStat Analytics plugin logs the malicious User-Agent string in the database without proper sanitization.
4.  An administrator enables the 'show_complete_user_agent_tooltip' setting in the SlimStat Analytics plugin configuration.
5.  A user visits a page where the User-Agent information is displayed via the tooltip.
6.  The stored XSS payload is rendered in the user's browser.
7.  The injected JavaScript code executes within the user's browser session.
8.  The attacker can then perform actions such as stealing cookies, redirecting the user, or defacing the website.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-7634) allows an unauthenticated attacker to execute arbitrary JavaScript code in the context of a user's browser. This can lead to session hijacking, defacement of the WordPress site, or redirection to malicious sites. The vulnerability is triggered when the administrator enables the 'show_complete_user_agent_tooltip' option, increasing the likelihood of exploitation if this setting is enabled. While the base score is 7.2, the impact can be significant depending on the privileges of the compromised user.

## Recommendation

*   Upgrade the SlimStat Analytics plugin to the latest version, which contains a fix for CVE-2026-7634.
*   Deploy the Sigma rule `Detect SlimStat User-Agent Header XSS Attempt` to identify attempts to inject malicious JavaScript in the User-Agent header.
*   Review the configuration of the SlimStat Analytics plugin and ensure that the `show_complete_user_agent_tooltip` setting is disabled if not needed.
