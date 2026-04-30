---
title: CSRF Vulnerability in WordPress Under Construction Plugin (CVE-2026-34896)
slug: 2026-04-wordpress-csrf
description: A cross-site request forgery (CSRF) vulnerability exists in the Analytify Under Construction, Coming Soon & Maintenance Mode WordPress plugin (versions n/a through 2.1.1), potentially allowing attackers to execute unauthorized actions on behalf of legitimate users.
date: "2026-04-07T09:16:21Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - wordpress
  - csrf
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34896
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34896
  - https://patchstack.com/database/wordpress/plugin/under-construction-maintenance-mode/vulnerability/wordpress-under-construction-coming-soon-maintenance-mode-plugin-2-1-1-cross-site-request-forgery-csrf-vulnerability?_s_id=cve
rules:
  - title: Detect WordPress Plugin Setting Changes via POST
    description: Detects POST requests to wp-admin/options.php indicating a potential plugin setting change, possibly indicative of CSRF attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Installation via POST
    description: Detects POST requests to wp-admin/plugin-install.php potentially indicating unauthorized plugin installation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A cross-site request forgery (CSRF) vulnerability, identified as CVE-2026-34896, affects the Analytify Under Construction, Coming Soon & Maintenance Mode WordPress plugin. This vulnerability allows an attacker to trick a user into performing actions they did not intend to, such as modifying plugin settings or performing administrative tasks, provided the targeted user is authenticated to the WordPress site. The vulnerability exists in versions from n/a through 2.1.1. The vulnerability was reported to affect a publicly available plugin, increasing the scope of potentially impacted websites. Successful exploitation could lead to arbitrary code execution depending on the privileges of the targeted user and plugin functionality that can be abused.

## Attack Chain

1. An attacker identifies a vulnerable WordPress site running the affected plugin.
2. The attacker crafts a malicious HTML page containing a CSRF exploit. This page contains a crafted HTTP request designed to trigger a specific action within the plugin (e.g., changing settings) when submitted by an authenticated user.
3. The attacker distributes the malicious HTML page via email, social media, or other means to a targeted WordPress administrator or user.
4. The targeted user, while logged into the vulnerable WordPress site, visits the malicious HTML page.
5. The user's browser automatically submits the crafted HTTP request to the WordPress site without the user's knowledge or consent.
6. The WordPress site, believing the request originated from the authenticated user, processes the request and executes the attacker's desired action.
7. The attacker's malicious action, such as changing plugin settings, is successfully performed on the vulnerable WordPress site.
8. Depending on the privileges of the compromised user and vulnerable plugin settings, the attacker may be able to achieve arbitrary code execution, site defacement, or data theft.

## Impact

Successful exploitation of this CSRF vulnerability (CVE-2026-34896) in the Analytify Under Construction, Coming Soon & Maintenance Mode WordPress plugin could lead to unauthorized modification of website settings, potentially resulting in site defacement, malware injection, or complete website takeover. The impact depends on the targeted user's privileges and the plugin's configurable options. While the exact number of affected websites is unknown, the plugin's popularity suggests a potentially broad impact across various sectors using WordPress for their online presence.

## Recommendation

*   Upgrade the Analytify Under Construction, Coming Soon & Maintenance Mode WordPress plugin to a version beyond 2.1.1 to patch CVE-2026-34896.
*   Deploy the Sigma rule `Detect WordPress Plugin Setting Changes via POST` to monitor for unauthorized changes to WordPress plugins.
*   Educate WordPress users on the risks of CSRF attacks and the importance of verifying the legitimacy of links and websites before clicking them.
