---
title: WordPress Mentoring Plugin Privilege Escalation Vulnerability
slug: 2026-05-wordpress-mentoring-privesc
description: The Mentoring plugin for WordPress is vulnerable to privilege escalation, allowing unauthenticated attackers to register with administrator-level user accounts due to improper role restriction in the mentoring_process_registration() function.
date: "2026-05-05T03:15:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - wordpress
  - plugin
vendors:
  - Wordpress
products:
  - Mentoring plugin for WordPress
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-13618
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-13618
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/7192fb4c-0434-4e11-a2a7-c205b8d6b68e?source=cve
rules:
  - title: Detect WordPress Mentoring Plugin Admin Registration
    description: Detects attempts to register a new admin user via the vulnerable Mentoring plugin registration endpoint.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Mentoring Plugin Registration Endpoint Access
    description: Detects access to the WordPress Mentoring plugin registration endpoint, which may indicate attempts to exploit privilege escalation vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Mentoring plugin for WordPress, versions 1.2.8 and earlier, contains a critical vulnerability (CVE-2025-13618) that allows unauthenticated attackers to escalate privileges. This flaw resides in the `mentoring_process_registration()` function, which fails to properly restrict the roles that new users can register with. By exploiting this vulnerability, an attacker can bypass authentication and directly create administrator accounts, granting them full control over the affected WordPress site. This vulnerability was reported by Wordfence.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable Mentoring plugin (version <= 1.2.8).
2. The attacker crafts a malicious HTTP POST request targeting the registration endpoint associated with the `mentoring_process_registration()` function.
3. The crafted request includes parameters designed to register a new user account with administrator privileges.
4. Due to the insufficient role validation within the `mentoring_process_registration()` function, the plugin allows the attacker to specify the 'administrator' role during registration.
5. The plugin creates a new user account in the WordPress database with the specified administrator role.
6. The attacker logs into the WordPress site using the newly created administrator account.
7. The attacker gains full control over the WordPress site, including the ability to modify content, install plugins, and manage user accounts.

## Impact

Successful exploitation of this vulnerability grants unauthenticated attackers complete administrative control over the affected WordPress website. This can lead to a range of malicious activities, including defacement, data theft, installation of malware, and denial of service. The impact is significant due to the ease of exploitation and the potential for widespread compromise of websites using the vulnerable plugin.

## Recommendation

*   Immediately update the Mentoring plugin for WordPress to the latest version (greater than 1.2.8) to patch CVE-2025-13618.
*   Deploy the Sigma rule `Detect WordPress Mentoring Plugin Admin Registration` to identify potential exploitation attempts targeting the `mentoring_process_registration()` function.
*   Monitor WordPress access logs for suspicious registration attempts targeting the vulnerable plugin.
