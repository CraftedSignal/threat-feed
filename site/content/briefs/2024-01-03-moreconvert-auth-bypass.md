---
title: MoreConvert Pro WordPress Plugin Authentication Bypass Vulnerability
slug: 2024-01-03-moreconvert-auth-bypass
description: The MoreConvert Pro plugin for WordPress versions 1.9.14 and earlier is vulnerable to authentication bypass due to improper handling of guest waitlist verification tokens, allowing unauthenticated attackers to potentially gain administrative access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authentication-bypass
  - plugin
  - cve-2026-5722
vendors:
  - WordPress
products:
  - MoreConvert Pro plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5722
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5722
rules:
  - title: Detect MoreConvert Pro Waitlist Email Change
    description: Detects attempts to change the email address associated with a guest waitlist entry, potentially indicating an authentication bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Successful Authentication with Guest Token
    description: Detects successful authentication attempts using a guest verification token, which may indicate exploitation of the authentication bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The MoreConvert Pro plugin, a WordPress extension, is vulnerable to an authentication bypass flaw (CVE-2026-5722) affecting all versions up to and including 1.9.14. The vulnerability stems from a failure to invalidate or regenerate guest waitlist verification tokens when a customer's email address is altered. This oversight enables a malicious actor to manipulate the waitlist verification process and impersonate existing users, potentially escalating privileges to gain administrative control over the WordPress site. This vulnerability poses a significant risk to WordPress sites using the MoreConvert Pro plugin, as unauthorized access could lead to data breaches, defacement, or complete site compromise.

## Attack Chain

1.  Attacker identifies a WordPress site using a vulnerable version (<= 1.9.14) of the MoreConvert Pro plugin.
2.  Attacker submits a request to join the guest waitlist using an email address they control (attacker@example.com).
3.  The plugin generates a verification token and sends a confirmation email to attacker@example.com.
4.  Attacker retrieves the valid verification token from their email.
5.  Attacker uses the public waitlist functionality to change the email address associated with the attacker@example.com entry to the email address of a target user, such as an administrator (admin@target.com).
6.  The plugin does not invalidate the original verification token.
7.  Attacker uses the original verification link containing the unchanged token.
8.  The plugin incorrectly authenticates the attacker as admin@target.com, granting them unauthorized access with the privileges of the targeted user.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to bypass authentication and gain unauthorized access to WordPress websites. This includes the ability to impersonate existing users, potentially including administrators. The CVSS v3.1 base score for this vulnerability is 9.8, indicating a critical severity. Consequences include full administrative control of the affected WordPress site, leading to potential data breaches, defacement, malware injection, and complete site compromise.

## Recommendation

*   Upgrade the MoreConvert Pro plugin to the latest available version (greater than 1.9.14) to patch CVE-2026-5722.
*   Monitor web server logs for suspicious requests to the waitlist functionality that involve email address changes and subsequent verification attempts. Deploy the Sigma rule `Detect MoreConvert Pro Waitlist Email Change` to detect this behavior.
*   Implement strong password policies and multi-factor authentication for all WordPress user accounts, especially administrator accounts, to mitigate the impact of potential account compromise.
*   Deploy the Sigma rule `Detect Successful Authentication with Guest Token` to identify successful authentication attempts using guest tokens.
