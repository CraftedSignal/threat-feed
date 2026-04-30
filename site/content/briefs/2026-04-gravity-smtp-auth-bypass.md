---
title: Gravity SMTP Plugin Missing Authorization Vulnerability (CVE-2026-4162)
slug: 2026-04-gravity-smtp-auth-bypass
description: The Gravity SMTP plugin for WordPress is vulnerable to Missing Authorization, allowing authenticated attackers with subscriber-level access or higher to uninstall/deactivate the plugin and delete plugin options, and is also exploitable via Cross-Site Request Forgery.
date: "2026-04-10T10:16:04Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - wordpress
  - missing-authorization
  - plugin
  - cve-2026-4162
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-4162
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4162
  - https://www.gravityforms.com/brand-new-release-gravity-smtp-2-1-5/
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/0f9d18a4-262b-4011-91e9-b29a27a76470?source=cve
rules:
  - title: Detect WordPress Plugin Uninstall via Missing Auth
    description: Detects attempts to uninstall a WordPress plugin via a missing authorization vulnerability. This rule identifies HTTP requests targeting the plugin management endpoint with the 'action=uninstall-plugin' parameter.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Plugin Options Deletion
    description: Detects attempts to delete WordPress plugin options, which can be indicative of exploitation attempts following a missing authorization vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Gravity SMTP plugin, a WordPress extension facilitating email sending through SMTP, contains a missing authorization vulnerability (CVE-2026-4162) affecting versions 2.1.4 and earlier. This flaw allows authenticated users with minimal subscriber-level permissions to perform administrative actions such as uninstalling and deactivating the plugin, as well as deleting its associated options. The vulnerability stems from the plugin failing to properly validate user authorization before executing sensitive functions. Additionally, the vulnerability can be exploited via a Cross-Site Request Forgery (CSRF) attack. Patches have been released in Gravity SMTP version 2.1.5 to address this security concern. Exploitation of this vulnerability allows low-privileged users to disrupt email functionality and potentially compromise WordPress configurations.

## Attack Chain

1. An attacker authenticates to the WordPress site with subscriber-level or higher privileges.
2. The attacker crafts a malicious HTTP request to uninstall the Gravity SMTP plugin, leveraging the missing authorization vulnerability. This request targets the WordPress plugin management endpoint.
3. Alternatively, the attacker crafts a CSRF attack that tricks a privileged user into triggering the malicious HTTP request to uninstall the plugin.
4. The WordPress server receives the crafted request without proper authorization checks.
5. The plugin's uninstall function is executed, removing the Gravity SMTP plugin from the WordPress installation.
6. The attacker crafts another HTTP request to delete Gravity SMTP plugin options.
7. The WordPress server processes the request, and the plugin options are deleted from the database.
8. The Gravity SMTP plugin is uninstalled and deactivated, and its settings are removed, disrupting the email functionality of the WordPress site.

## Impact

Successful exploitation of CVE-2026-4162 allows attackers with low-level privileges on a WordPress site to disable email functionality and manipulate plugin settings. While the number of affected installations remains unknown, the impact can be significant for organizations heavily reliant on WordPress for communication or critical business processes, potentially leading to disruption of services, loss of email functionality, and unauthorized access to sensitive data or configurations. The CVSS v3.1 score of 7.1 indicates a high severity, considering the ease of exploitation and the potential for widespread disruption.

## Recommendation

*   Upgrade the Gravity SMTP plugin to version 2.1.5 or later to patch CVE-2026-4162.
*   Monitor WordPress access logs for unauthorized requests targeting the plugin management endpoints to detect potential exploitation attempts. Deploy the Sigma rule `Detect WordPress Plugin Uninstall via Missing Auth` to identify suspicious activity.
*   Implement CSRF protection mechanisms within WordPress plugins to mitigate the risk of CSRF-based exploitation.
*   Review WordPress user roles and permissions to minimize the attack surface and restrict access to sensitive functionalities.
