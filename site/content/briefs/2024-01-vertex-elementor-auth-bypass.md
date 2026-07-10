---
title: Vertex Addons for Elementor WordPress Plugin Missing Authorization Vulnerability (CVE-2026-4326)
slug: 2024-01-vertex-elementor-auth-bypass
description: The Vertex Addons for Elementor plugin for WordPress up to version 1.6.4 is vulnerable to missing authorization, allowing authenticated attackers with subscriber-level access to install and activate arbitrary plugins.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - missing-authorization
  - privilege-escalation
  - cve-2026-4326
  - webserver
vendors:
  - Vertex Addons
products:
  - Vertex Addons for Elementor
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4326
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4326
rules:
  - title: Detect Vertex Elementor Plugin Install Attempt via AJAX
    description: Detects attempts to exploit the Vertex Addons for Elementor plugin vulnerability by monitoring requests to the admin-ajax.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Installation via Subscriber
    description: Detects WordPress plugin installations initiated by users with subscriber-level privileges.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Vertex Addons for Elementor plugin, a WordPress extension, is susceptible to a critical missing authorization vulnerability (CVE-2026-4326) affecting versions up to and including 1.6.4. This flaw stems from a failure to properly validate user permissions within the `activate_required_plugins()` function. Although the code checks for the `install_plugins` capability, it does not halt execution upon failure, allowing unauthorized plugin installation and activation to proceed.  The vulnerability enables authenticated attackers with as little as subscriber-level access to install and activate plugins from the WordPress repository. This poses a significant risk, as malicious plugins can compromise the entire WordPress site, leading to complete system takeover, data theft, or defacement. This vulnerability requires immediate attention from website administrators using the vulnerable plugin.

## Attack Chain

1.  Attacker gains subscriber-level access to a WordPress site running the vulnerable Vertex Addons for Elementor plugin (version <= 1.6.4). This could be achieved through compromised credentials or by simply registering a new user account if registration is enabled.
2.  Attacker crafts a malicious request to trigger the `activate_required_plugins()` function. This request would typically be sent to the WordPress admin-ajax.php endpoint.
3.  The `activate_required_plugins()` function executes, initiating a capability check via `current_user_can('install_plugins')`.
4.  The capability check fails because a subscriber does not have the `install_plugins` capability. However, the code does not terminate execution at this point.
5.  The code proceeds to install and activate a plugin specified in the attacker's request. The plugin is retrieved from the WordPress plugin repository.
6.  The malicious plugin is activated and its code is executed, granting the attacker complete control over the WordPress site.
7.  The attacker leverages the plugin to inject malicious code, create administrative accounts, or exfiltrate sensitive data.
8.  The attacker successfully escalates privileges to administrator level and gains full control of the WordPress installation.

## Impact

Successful exploitation of CVE-2026-4326 allows attackers with minimal privileges (subscriber) to install and activate arbitrary plugins on a WordPress site. This leads to complete site compromise, including the potential for data theft, defacement, or deployment of malicious code to visitors. The number of affected websites depends on the install base of the Vertex Addons for Elementor plugin. Given the severity, any unpatched website is at immediate risk of complete takeover.

## Recommendation

*   Immediately update the Vertex Addons for Elementor plugin to the latest available version, which includes a patch for CVE-2026-4326.
*   Monitor web server logs for suspicious requests to the `admin-ajax.php` endpoint, specifically those targeting the `activate_required_plugins()` function. Implement the Sigma rule `Detect Vertex Elementor Plugin Install Attempt via AJAX` to identify such attempts.
*   Implement the Sigma rule `Detect WordPress Plugin Installation via Subscriber` to detect plugin installations performed by users with subscriber-level privileges.
*   Restrict WordPress user registration to trusted individuals. If user registration is necessary, consider implementing stricter account verification and monitoring procedures.
