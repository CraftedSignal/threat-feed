---
title: 'CVE-2026-27384: W3 Total Cache Unauthenticated RCE via eval() Code Injection'
slug: 2026-05-w3-total-cache-rce
description: A public exploit has been published for CVE-2026-27384, a critical unauthenticated remote code execution vulnerability in the W3 Total Cache WordPress plugin.
date: "2026-05-26T11:01:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - wordpress
  - code-injection
  - eval
  - w3-total-cache
vendors:
  - WordPress
products:
  - W3 Total Cache < 2.9.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://sploitus.com/exploit?id=DC293067-63CE-5FC7-85EA-9914991344BC&utm_source=rss&utm_medium=rss
  - https://www.wordfence.com/threat-intel/vulnerabilities/
  - https://wordpress.org/plugins/w3-total-cache/
  - https://code-white.com
  - https://cwe.mitre.org/data/definitions/94.html
  - https://owasp.org/www-community/attacks/Code_Injection
  - https://www.php.net/manual/en/function.eval.php
  - https://www.php.net/manual/en/function.preg-quote.php
rules:
  - title: Detect CVE-2026-27384 Exploitation Attempt — mfunc Tag in POST Request
    description: Detects CVE-2026-27384 exploitation attempts by identifying POST requests to comment submission endpoints containing mfunc tags, indicating potential code injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1189
    data_sources:
      - webserver
  - title: Detect CVE-2026-27384 Exploitation Attempt —  W3 Total Cache mfunc eval RCE - Response Contains User ID
    description: Detects CVE-2026-27384 exploitation via the presence of  'uid=' within the response from the webserver.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

A public exploit has been released for CVE-2026-27384, a critical vulnerability in the W3 Total Cache WordPress plugin (versions prior to 2.9.2). This vulnerability allows unauthenticated attackers to execute arbitrary PHP code on the server. The vulnerability lies in the Dynamic Fragment Caching feature (`mfunc/mclude` system). The vulnerability is due to a combination of factors, including the lack of `preg_quote()` in sanitizing the `W3TC_DYNAMIC_SECURITY` token, an inconsistency between `\s*` and `\s+` in regex matching, and missing token validation. An attacker can exploit this vulnerability by injecting malicious PHP code into a WordPress comment. The exploit was published on Sploitus and assigned a CVSS score of 9.8 (Critical).

## Attack Chain

1.  The attacker identifies a WordPress site running a vulnerable version of the W3 Total Cache plugin (versions prior to 2.9.2).
2.  The attacker crafts a malicious WordPress comment containing PHP code within `mfunc` tags, designed to bypass the `strip_dynamic_fragment_tags_from_string()` function due to the space mismatch vulnerability (\s* vs \s+).
3.  The attacker posts the crafted comment to a vulnerable page on the WordPress site.
4.  The WordPress site saves the comment, including the malicious payload, to the database and caches the page.
5.  A second HTTP request to the cached page triggers the W3 Total Cache plugin to process the cached content.
6.  The `_has_dynamic()` function checks for the existence of the `W3TC_DYNAMIC_SECURITY` constant but lacks proper validation, allowing the payload to proceed.
7.  The `_parse_dynamic()` function, due to the missing `preg_quote()` function, incorrectly parses the token, leading to code injection.
8.  The `_parse_dynamic_mfunc()` function executes the injected PHP code using `eval()`, resulting in unauthenticated remote code execution. The attacker can then perform actions such as gaining shell access, reading sensitive files, and compromising the server.

## Impact

Successful exploitation of CVE-2026-27384 allows an unauthenticated attacker to execute arbitrary PHP code on the affected server with the privileges of the web server user. This can lead to full server compromise, unauthorized access to the WordPress database and files, installation of a web shell for persistent access, and potential pivoting to internal networks. Since it is an unauthenticated vulnerability, any visitor can post a comment that injects malicious PHP code.

## Recommendation

*   Upgrade the W3 Total Cache plugin to version 2.9.2 or later to patch CVE-2026-27384.
*   If upgrading is not immediately possible, define a strong, alphanumeric `W3TC_DYNAMIC_SECURITY` token in the `wp-config.php` file as a temporary mitigation.
*   Monitor web server logs for suspicious POST requests to comment submission endpoints (`/wp-comments-post.php`, `/wp-json/wp/v2/comments`) with payloads containing `mfunc` and `shell_exec`, as detailed in the attack chain (enable webserver logging to activate related rules).
