---
title: BuddyPress Groupblog Plugin Privilege Escalation Vulnerability (CVE-2026-5144)
slug: 2026-04-buddypress-privesc
description: The BuddyPress Groupblog plugin for WordPress is vulnerable to privilege escalation (CVE-2026-5144), allowing a low-privileged user to gain administrator access on a WordPress Multisite network by manipulating group blog settings.
date: "2026-04-11T02:19:36Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - wordpress
  - buddypress
  - privilege-escalation
  - cve-2026-5144
  - cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-5144
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5144
rules:
  - title: Detect BuddyPress Groupblog Privilege Escalation Attempt via HTTP POST
    description: Detects attempts to exploit CVE-2026-5144 by monitoring HTTP POST requests to options.php with suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect BuddyPress Groupblog Privilege Escalation - User Role Change
    description: Detects potential privilege escalation by monitoring for user role changes to 'administrator' after suspicious activity.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The BuddyPress Groupblog plugin, versions 1.9.3 and below, contains a critical privilege escalation vulnerability (CVE-2026-5144). This flaw allows authenticated attackers with minimal privileges (Subscriber or higher) to escalate privileges to Administrator on the main WordPress Multisite site. The vulnerability stems from a lack of authorization checks in the group blog settings handler. Specifically, the plugin improperly validates the `groupblog-blogid`, `default-member`, and `groupblog-silent-add` parameters. This vulnerability allows an attacker to associate their group with the main site (blog ID 1) and automatically assign the 'administrator' role to new group members. Successful exploitation grants attackers full control over the WordPress Multisite network, posing a significant risk to data confidentiality, integrity, and availability.

## Attack Chain

1.  Attacker creates a new group on the WordPress Multisite network with a Subscriber account.
2.  Attacker accesses the group's settings page.
3.  Attacker modifies the `groupblog-blogid` parameter, setting it to "1" to associate the group with the main site. This is done by crafting a malicious HTTP POST request to the group settings handler.
4.  The attacker modifies the `default-member` parameter to "administrator". This parameter controls the default role assigned to new members.
5.  The attacker enables the `groupblog-silent-add` parameter. This setting automatically adds new group members to the associated blog (main site) with the specified default role (administrator).
6.  Attacker creates a second user account or convinces another user to join their malicious group.
7.  When the new user joins the attacker's group, the `groupblog-silent-add` setting automatically adds the new user to the main site with the administrator role.
8.  The attacker (via the new user account) now has administrator access to the main WordPress Multisite site.

## Impact

Successful exploitation of CVE-2026-5144 grants an attacker complete control over the targeted WordPress Multisite network. This allows them to modify content, install malicious plugins, create new administrator accounts, and potentially compromise the underlying server. The impact is especially severe for organizations relying on WordPress Multisite for critical applications, as it can lead to data breaches, service disruptions, and significant financial losses. The vulnerability affects all installations using the BuddyPress Groupblog plugin up to version 1.9.3, potentially impacting thousands of websites.

## Recommendation

*   Immediately update the BuddyPress Groupblog plugin to a version greater than 1.9.3 to patch CVE-2026-5144.
*   Monitor web server logs for POST requests to `/wp-admin/options.php` with parameters `groupblog-blogid`, `default-member`, and `groupblog-silent-add` to detect potential exploitation attempts, using the provided Sigma rule.
*   Implement strict access control policies to limit the ability of low-privileged users to modify group settings and install plugins.
*   Enable logging of user role changes to detect unauthorized privilege escalation attempts.
