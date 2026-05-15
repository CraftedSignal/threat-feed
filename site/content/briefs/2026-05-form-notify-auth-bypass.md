---
title: WordPress Form Notify Plugin Authentication Bypass Vulnerability (CVE-2026-5229)
slug: 2026-05-form-notify-auth-bypass
description: The Form Notify plugin for WordPress is vulnerable to CVE-2026-5229, an authentication bypass, due to trusting user-controlled cookie data after a LINE OAuth login, allowing unauthenticated attackers to gain administrative access.
date: "2026-05-15T09:18:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - wordpress
  - plugin
  - CVE-2026-5229
vendors:
  - WordPress
products:
  - Form Notify <= 1.1.10
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-5229
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5229
rules:
  - title: Detect WordPress Form Notify Authentication Bypass via Malicious Cookie
    description: Detects CVE-2026-5229 exploitation — Authentication bypass in WordPress Form Notify plugin due to malicious form_notify_line_email cookie
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1550.002
    data_sources:
      - webserver
  - title: Detect Possible WordPress Form Notify Authentication Bypass - LINE OAuth
    description: Detects potential CVE-2026-5229 exploitation attempts by monitoring for LINE OAuth login requests without an associated email.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1550.002
    data_sources:
      - webserver
rules_count: 2
---

The Form Notify plugin for WordPress is vulnerable to an authentication bypass vulnerability, identified as CVE-2026-5229, in versions up to and including 1.1.10. The vulnerability stems from the plugin's flawed logic in handling LINE OAuth logins. Specifically, when LINE does not provide an email address for a user, the plugin relies on the 'form_notify_line_email' cookie to determine the WordPress account to authenticate. The plugin fails to validate that the LINE account is actually associated with the email address provided in the cookie, enabling attackers to forge the cookie value. This makes it possible for an unauthenticated attacker to gain access to any user account on the WordPress site, including those with administrator privileges.

## Attack Chain

1.  The attacker identifies a WordPress site using a vulnerable version (<= 1.1.10) of the Form Notify plugin.
2.  The attacker registers a LINE OAuth account.
3.  The attacker initiates a LINE OAuth login flow on the target WordPress site.
4.  The LINE OAuth flow does not provide an email address (this is a common scenario).
5.  Before completing the login, the attacker injects a malicious 'form_notify_line_email' cookie into their browser session, setting the value to the email address of the target victim's WordPress account (e.g., the administrator's email).
6.  The attacker completes the LINE OAuth login process on the WordPress site.
7.  The Form Notify plugin reads the 'form_notify_line_email' cookie and, without proper verification, authenticates the attacker as the victim user.
8.  The attacker now has full access to the victim's WordPress account, potentially gaining administrative control of the entire site.

## Impact

Successful exploitation of CVE-2026-5229 allows unauthenticated attackers to bypass authentication and gain unauthorized access to WordPress accounts, including administrator accounts. This can lead to complete compromise of the WordPress site, including data theft, defacement, malware injection, and denial of service. The severity is high due to the ease of exploitation and the potential for widespread impact, particularly on sites relying on the Form Notify plugin for critical functionality.

## Recommendation

*   Apply available patches or upgrade Form Notify plugin to a version greater than 1.1.10 to remediate CVE-2026-5229.
*   Deploy the Sigma rule `Detect WordPress Form Notify Authentication Bypass via Malicious Cookie` to your SIEM to detect potential exploitation attempts (see below).
*   Monitor web server logs for suspicious POST requests with manipulated `form_notify_line_email` cookies.
