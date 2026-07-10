---
title: WP Statistics Plugin Stored XSS Vulnerability (CVE-2026-5231)
slug: 2024-01-26-wp-statistics-xss
description: The WP Statistics WordPress plugin is vulnerable to stored cross-site scripting (XSS) via the 'utm_source' parameter, allowing unauthenticated attackers to inject arbitrary web scripts into admin pages.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - cve-2026-5231
  - wp-statistics
vendors:
  - WP Statistics
products:
  - WP Statistics
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
cves:
  - id: CVE-2026-5231
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5231
rules:
  - title: Detect Suspicious utm_source Parameter
    description: Detects requests with potentially malicious payloads in the utm_source parameter, indicative of XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious URI Containing utm_source Parameter
    description: Detects requests with a potentially malicious utm_source parameter in the URI.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WP Statistics plugin for WordPress, versions up to and including 14.16.4, is susceptible to a stored cross-site scripting (XSS) vulnerability identified as CVE-2026-5231. This flaw stems from inadequate input sanitization and output escaping of the 'utm_source' parameter. The vulnerability is triggered because the plugin's referral parser copies the unsanitized 'utm_source' value directly into the 'source_name' field when a wildcard channel domain matches. Subsequently, the chart renderer uses this value in the legend markup via innerHTML without proper escaping. This allows unauthenticated attackers to inject malicious JavaScript code, which executes within the context of an administrator's browser when they access the Referrals Overview or Social Media analytics pages within the WordPress admin panel. This poses a significant risk to the confidentiality and integrity of the WordPress site.

## Attack Chain

1. An unauthenticated attacker crafts a malicious URL containing a JavaScript payload within the `utm_source` parameter.
2. A user visits the website using the malicious URL, triggering the WP Statistics plugin's referral parser.
3. The plugin's referral parser processes the URL and copies the unsanitized `utm_source` value, including the injected JavaScript, into the `source_name` field in the database.
4. An administrator logs into the WordPress admin panel.
5. The administrator navigates to the Referrals Overview or Social Media analytics pages, which utilize the WP Statistics plugin's chart renderer.
6. The chart renderer retrieves the `source_name` field from the database, which contains the injected JavaScript.
7. The chart renderer inserts the malicious JavaScript into the legend markup via innerHTML without proper escaping.
8. The administrator's browser executes the injected JavaScript, potentially allowing the attacker to perform actions such as stealing administrator cookies, modifying website content, or redirecting the administrator to a malicious website.

## Impact

Successful exploitation of this stored XSS vulnerability allows an unauthenticated attacker to execute arbitrary JavaScript code within the context of an administrator's browser. This could lead to complete compromise of the WordPress website, including unauthorized access to sensitive data, modification of website content, and installation of malicious plugins or themes. The impact is significant due to the widespread use of the WP Statistics plugin and the potential for attackers to gain complete control over affected websites. While no specific victim numbers are available, the large user base of WordPress suggests a potentially broad impact across various sectors.

## Recommendation

*   Apply the latest patch or upgrade to a version of the WP Statistics plugin that addresses CVE-2026-5231 to remediate the vulnerability.
*   Deploy the provided Sigma rule `Detect Suspicious utm_source Parameter` to identify potential exploitation attempts targeting the `utm_source` parameter in web server logs.
*   Implement input validation and output escaping mechanisms within the WP Statistics plugin to prevent similar XSS vulnerabilities in the future.
*   Monitor web server logs for requests containing suspicious characters or patterns within the `utm_source` parameter, as highlighted in the Sigma rule.
