---
title: WordPress Temporary Login Plugin Authentication Bypass Vulnerability
slug: 2026-05-wordpress-temp-login-auth-bypass
description: A public exploit is available for WordPress Temporary Login Plugin version 1.0.0, which demonstrates an authentication bypass vulnerability that can lead to account takeover, increasing the risk for unpatched systems.
date: "2026-05-26T15:01:40Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - authentication-bypass
  - account-takeover
  - webapps
vendors:
  - WordPress
products:
  - Temporary Login Plugin 1.0.0
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://www.exploit-db.com/exploits/52575
rules:
  - title: Detect Wordpress Temporary Login Plugin Authentication Bypass Attempt
    description: Detects attempts to exploit the WordPress Temporary Login Plugin authentication bypass vulnerability by looking for specific URI patterns in web server logs.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1556
    data_sources:
      - webserver
  - title: Detect Wordpress Administrator Account Takeover
    description: Detects potential WordPress administrator account takeover by monitoring for admin dashboard access from unusual IP addresses.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1556
    data_sources:
      - webserver
rules_count: 2
---

A public exploit, EDB-52575, has been published on Exploit-DB targeting the WordPress Temporary Login Plugin version 1.0.0. This exploit demonstrates a 'temp-login-token' Authentication Bypass vulnerability that allows for Account Takeover. The vulnerability allows an attacker to bypass authentication mechanisms, granting them unauthorized access to user accounts. The availability of a working exploit significantly elevates the risk for unpatched WordPress sites using the affected plugin version. This poses a serious threat as attackers can gain administrative privileges, modify website content, steal sensitive data, or use the compromised site to launch further attacks.

## Attack Chain

1.  The attacker identifies a WordPress website using the vulnerable Temporary Login Plugin version 1.0.0.
2.  The attacker crafts a malicious request, exploiting the 'temp-login-token' authentication bypass vulnerability.
3.  The crafted request is sent to the WordPress server, bypassing normal authentication checks.
4.  The vulnerable plugin fails to properly validate the 'temp-login-token', granting the attacker unauthorized access.
5.  The attacker gains access to a user account, potentially an administrator account, without providing valid credentials.
6.  With compromised credentials, the attacker logs into the WordPress dashboard.
7.  The attacker modifies website content, installs malicious plugins, or exfiltrates sensitive data.
8.  The attacker achieves complete control over the compromised WordPress website.

## Impact

Successful exploitation of this vulnerability allows attackers to take complete control of vulnerable WordPress websites. This can lead to data theft, website defacement, malware distribution, and further compromise of connected systems. Given the widespread use of WordPress, a large number of websites are potentially vulnerable, particularly those that have not yet updated the Temporary Login Plugin to a patched version. The impact could range from reputational damage to significant financial losses for affected website owners.

## Recommendation

*   Immediately update the WordPress Temporary Login Plugin to a version that patches the authentication bypass vulnerability on all affected websites.
*   Deploy the Sigma rule "Detect Wordpress Temporary Login Plugin Authentication Bypass Attempt" to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests containing 'temp-login-token' parameters and unusual activity, as described in the Attack Chain section.
*   Consider implementing a web application firewall (WAF) rule to block requests that attempt to exploit the authentication bypass vulnerability.
