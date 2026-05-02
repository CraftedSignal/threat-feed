---
title: WP Mail Gateway Plugin Vulnerability Leads to Privilege Escalation
slug: 2026-05-wp-mail-gateway-privesc
description: The WP Mail Gateway plugin for WordPress is vulnerable to unauthorized access due to a missing capability check, allowing authenticated attackers to modify SMTP settings and escalate privileges.
date: "2026-05-02T05:16:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - privilege-escalation
  - plugin-vulnerability
vendors:
  - WordPress
products:
  - WP Mail Gateway plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6963
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6963
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/c7caf1f4-a8dd-4016-91eb-2adbeed5290a?source=cve
rules:
  - title: Detect Suspicious AJAX Request to wmg_save_provider_config
    description: Detects unauthorized AJAX requests to the wmg_save_provider_config endpoint, indicating potential exploitation of CVE-2026-6963
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Modification of WordPress SMTP Options
    description: Detects changes to WordPress options related to SMTP configuration, potentially indicating exploitation of the vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The WP Mail Gateway plugin, a WordPress extension, contains a vulnerability (CVE-2026-6963) that allows authenticated users with minimal privileges (Subscriber level or higher) to gain administrative access. The flaw resides in the `wmg_save_provider_config` AJAX action, which lacks proper authorization checks. This omission enables attackers to manipulate SMTP settings, redirect outgoing emails, and ultimately trigger password reset emails intended for administrators. The vulnerability affects all versions of the WP Mail Gateway plugin up to and including version 1.8. Successful exploitation grants attackers complete control over the WordPress site, making it a critical security concern for any organization using the vulnerable plugin.

## Attack Chain

1. An attacker logs into a WordPress site with a Subscriber-level account or higher.
2. The attacker crafts a malicious AJAX request targeting the `wmg_save_provider_config` action.
3. This request modifies the SMTP settings, redirecting outgoing emails to an attacker-controlled server.
4. The attacker initiates a password reset request for an administrator account.
5. The password reset email is intercepted by the attacker's server.
6. The attacker uses the password reset link to gain access to the administrator's account.
7. The attacker logs into the WordPress dashboard with administrator privileges.
8. The attacker can now perform any administrative action, including installing malicious plugins, modifying site content, or creating new administrator accounts.

## Impact

Successful exploitation of CVE-2026-6963 allows an attacker to completely compromise a WordPress website.  Even low-privileged users can elevate their access to administrator, giving them full control over the site.  This can lead to data breaches, website defacement, malware deployment, and other malicious activities. The vulnerability affects all installations of the WP Mail Gateway plugin up to version 1.8, potentially impacting thousands of WordPress sites.

## Recommendation

*   Upgrade the WP Mail Gateway plugin to a version beyond 1.8 to patch CVE-2026-6963.
*   Monitor WordPress logs for suspicious AJAX requests targeting the `wmg_save_provider_config` action using the Sigma rule provided below. Enable webserver logging to capture HTTP POST requests.
*   Implement the provided Sigma rule to detect modifications to WordPress options related to SMTP configuration. Enable relevant logging for registry modifications.
