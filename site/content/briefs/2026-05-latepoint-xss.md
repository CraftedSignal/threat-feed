---
title: LatePoint WordPress Plugin Vulnerable to Stored XSS (CVE-2026-7448)
slug: 2026-05-latepoint-xss
description: The LatePoint WordPress plugin is vulnerable to stored cross-site scripting (XSS) via the 'first_name' parameter, affecting versions up to 5.5.0, allowing unauthenticated attackers to inject malicious scripts.
date: "2026-05-06T08:16:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - cve-2026-7448
vendors:
  - Wordfence
products:
  - LatePoint – Calendar Booking Plugin for Appointments and Events <= 5.5.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-7448
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7448
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/c8eedec9-d8d4-4052-baec-29f83ac306ac?source=cve
rules:
  - title: Detect LatePoint XSS Attempt
    description: Detects potential attempts to exploit the LatePoint plugin XSS vulnerability by identifying requests with JavaScript code in the 'first_name' parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect LatePoint XSS Attempt - POST Method
    description: Detects potential attempts to exploit the LatePoint plugin XSS vulnerability via POST requests with JavaScript code in the 'first_name' parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-7448 identifies a stored cross-site scripting (XSS) vulnerability in the LatePoint – Calendar Booking Plugin for Appointments and Events plugin for WordPress. The vulnerability exists due to insufficient input sanitization and output escaping of the 'first_name' parameter. This flaw allows unauthenticated attackers to inject arbitrary JavaScript code into the WordPress site. Successful exploitation of this vulnerability enables attackers to execute malicious scripts in a user's browser when they access the affected page. This can lead to session hijacking, defacement of the website, or redirection to malicious sites. All versions of the LatePoint plugin up to and including 5.5.0 are affected.

## Attack Chain

1. An unauthenticated attacker crafts a malicious request containing JavaScript code in the `first_name` parameter.
2. The attacker sends the crafted request to the WordPress server hosting the vulnerable LatePoint plugin.
3. The LatePoint plugin processes the request without proper sanitization of the `first_name` parameter.
4. The unsanitized input is stored in the WordPress database.
5. A user accesses a page that displays the stored data from the `first_name` field.
6. The malicious JavaScript code is executed in the user's browser.
7. The attacker can potentially steal cookies, redirect the user to a malicious website, or deface the website.

## Impact

Successful exploitation of this vulnerability can lead to a variety of negative consequences, including account compromise, defacement of the website, and the potential spread of malware to users. The vulnerability affects all users of the LatePoint plugin up to version 5.5.0. Given the popularity of WordPress and the LatePoint plugin, a large number of websites are potentially vulnerable.

## Recommendation

*   Upgrade the LatePoint – Calendar Booking Plugin for Appointments and Events to a version greater than 5.5.0 to patch CVE-2026-7448.
*   Deploy the Sigma rule `Detect LatePoint XSS Attempt` to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious requests containing JavaScript code in the `first_name` parameter.
