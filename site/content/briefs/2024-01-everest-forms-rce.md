---
brief_id: brief-2024-01-26-everest-forms-rce
event_id: brief-2024-01-26-everest-forms-rce
revision: 1
activity_at: "2024-01-26T12:00:00Z"
title: Everest Forms Pro Plugin Remote Code Execution via PHP Injection
slug: 2024-01-everest-forms-rce
description: The Everest Forms Pro plugin for WordPress is vulnerable to remote code execution (RCE) due to a PHP Code Injection vulnerability (CVE-2026-3300) allowing unauthenticated attackers to execute arbitrary PHP code by exploiting insufficient input sanitization in the 'Complex Calculation' feature, affecting versions up to 1.9.12.
date: "2024-01-26T12:00:00Z"
lastmod: "2026-11-13T09:13:25Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ADAMSHAIKHMA-CVE-2026-3300&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - rce
  - php-injection
  - cve-2026-3300
vendors:
  - Everest Forms
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-3300
    cvss: 9.8
    epss: 0.39159
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3300
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ADAMSHAIKHMA-CVE-2026-3300&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Everest Forms Pro PHP Injection
    description: Detects potential PHP code injection attempts targeting the Everest Forms Pro plugin by identifying suspicious POST requests containing PHP code in form field values.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect PHP code execution via eval() function
    description: Detects potential PHP code execution through eval() function in web server logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-11-13T09:13:25Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ADAMSHAIKHMA-CVE-2026-3300&utm_source=rss&utm_medium=rss
---

The Everest Forms Pro plugin, a popular WordPress form builder, contains a critical vulnerability (CVE-2026-3300) leading to Remote Code Execution (RCE). Present in versions up to and including 1.9.12, the vulnerability stems from inadequate input sanitization within the Calculation Addon's `process_filter()` function. Specifically, user-submitted form field values are directly concatenated into a PHP code string without proper escaping, which is then processed by the `eval()` function. The `sanitize_text_field()` function does not adequately neutralize single quotes or other characters crucial for preventing code injection. Successful exploitation grants unauthenticated attackers the ability to execute arbitrary PHP code on the server hosting the WordPress instance. This can lead to complete system compromise, data theft, and website defacement.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress website using a vulnerable version of the Everest Forms Pro plugin (<= 1.9.12) with the 'Complex Calculation' feature enabled on a form.
2.  The attacker crafts a malicious payload containing PHP code designed to execute system commands. This payload leverages PHP's `eval()` function and injects code using single quotes and other PHP context characters.
3.  The crafted payload is submitted via a string-type form field (e.g., text, email, URL) within the vulnerable form.
4.  The Everest Forms Pro plugin's `process_filter()` function processes the submitted data. The `sanitize_text_field()` function fails to properly escape the malicious payload.
5.  The malicious payload is concatenated into a PHP code string and passed to the `eval()` function.
6.  The `eval()` function executes the injected PHP code, allowing the attacker to execute arbitrary commands on the server.
7.  The attacker can then perform actions such as reading sensitive files, installing backdoors, or modifying website content.
8.  The attacker gains persistent access to the web server, enabling further malicious activities and potentially compromising the entire system.

## Impact

Successful exploitation of this vulnerability (CVE-2026-3300) can lead to complete compromise of the WordPress website and the underlying server. Attackers can gain unauthorized access to sensitive data, including user credentials and financial information. They can deface websites, inject malware, and use the compromised server as a launchpad for further attacks. Given the widespread use of Everest Forms Pro, a large number of WordPress websites are potentially vulnerable, with the exact number of victims depending on the adoption rate of the affected versions. A successful RCE can result in significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Upgrade the Everest Forms Pro plugin to the latest version (greater than 1.9.12) to patch CVE-2026-3300.
*   Implement the Sigma rule `Detect Everest Forms Pro PHP Injection` to identify potential exploitation attempts in web server logs.
*   Review WordPress web server logs for suspicious POST requests to `/wp-admin/admin-ajax.php` containing PHP code in form field values, and investigate any identified anomalies.
*   Apply input validation and output encoding to all user-supplied data within WordPress plugins to prevent code injection vulnerabilities.
