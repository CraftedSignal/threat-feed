---
title: CVE-2026-12153 — WP Learn Manager Plugin Authorization Bypass
slug: 2026-07-wp-learn-manager-auth-bypass
description: The WP Learn Manager plugin for WordPress, in versions up to and including 1.1.8, is vulnerable to an authorization bypass (CVE-2026-12153) allowing unauthenticated attackers to install and activate arbitrary plugins from the WordPress.org repository, potentially leading to full site compromise.
date: "2026-07-08T06:21:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - authorization-bypass
  - cve
  - web-application
  - critical-vulnerability
vendors:
  - rabilal
products:
  - WP Learn Manager <= 1.1.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated attackers to install and activate arbitrary plugins from the WordPress.org repository on the vulnerable site.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to install and activate arbitrary plugins from the WordPress.org repository on the vulnerable site.
    confidence_band: high
cves:
  - id: CVE-2026-12153
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12153
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/8cbf5121-2511-4e21-a346-67fa1e34fc02?source=cve
rules:
  - title: Detects CVE-2026-12153 Exploitation — Unauthenticated WP Learn Manager Plugin Actions
    description: Detects exploitation attempts against CVE-2026-12153, where unauthenticated attackers attempt to install or activate WordPress plugins via the vulnerable WP Learn Manager plugin's AJAX endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-12153 addresses a critical authorization bypass vulnerability affecting all versions of the WP Learn Manager plugin for WordPress, specifically up to and including 1.1.8. The flaw stems from the plugin's failure to adequately verify user authorization prior to executing certain actions. This critical oversight enables unauthenticated attackers to leverage vulnerable endpoints to install and activate arbitrary plugins directly from the WordPress.org repository on the compromised site. The ability to install and activate arbitrary plugins provides a clear path to achieving unauthenticated Remote Code Execution (RCE) or complete site takeover by installing a malicious plugin. This vulnerability poses a severe risk to WordPress sites utilizing the affected plugin, allowing attackers to gain control without requiring any prior authentication or credentials.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site running the vulnerable WP Learn Manager plugin (version 1.1.8 or earlier).
2.  The attacker crafts a malicious HTTP POST request targeting the `wp-admin/admin-ajax.php` endpoint, which handles AJAX requests for WordPress and plugins.
3.  The crafted request includes parameters specifically designed to invoke plugin installation or activation actions, such as `action=install-plugin` or `action=activate-plugin`, exploiting the WP Learn Manager's missing authorization checks.
4.  The attacker specifies a plugin name or slug from the official WordPress.org repository within the request, which could be a legitimate but vulnerable plugin, or one with known backdoors.
5.  Due to the authorization bypass in WP Learn Manager, the WordPress core or the plugin proceeds to process the request without verifying the attacker's administrative privileges.
6.  The WordPress site then downloads, installs, and activates the attacker-specified plugin from the WordPress.org repository.
7.  Upon activation, if the installed plugin contains malicious code (e.g., a web shell, backdoor, or configuration changes), the attacker gains persistent access or achieves unauthenticated Remote Code Execution (RCE) on the server.
8.  The attacker can then perform further malicious actions, such as data exfiltration, defacement, or embedding malware for visitor compromise.

## Impact

The impact of successful exploitation of CVE-2026-12153 is severe, rated with a CVSS v3.1 base score of 9.8 (Critical). An unauthenticated attacker can achieve complete compromise of the affected WordPress site, potentially leading to unauthenticated Remote Code Execution (RCE). This could result in unauthorized access to sensitive data, website defacement, arbitrary code execution on the underlying server, and the ability to inject malware that could infect site visitors. Given the ease of exploitation and the lack of authentication required, affected organizations face a high risk of significant data breaches, operational disruption, and reputational damage if their sites are compromised.

## Recommendation

*   Immediately update the WP Learn Manager plugin to a patched version beyond 1.1.8 to remediate CVE-2026-12153.
*   Deploy the provided Sigma rule to detect attempts at exploiting this authorization bypass on your web server logs.
*   Monitor WordPress activity logs for unusual or unauthenticated plugin installations or activations that could indicate successful exploitation.
*   Regularly review installed plugins and themes on all WordPress sites for legitimacy and remove any unknown or unauthorized components.
