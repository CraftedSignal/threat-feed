---
title: BuddyPress Groupblog Plugin Privilege Escalation Vulnerability (CVE-2026-5144)
slug: 2026-04-buddypress-privesc
description: The BuddyPress Groupblog plugin for WordPress is vulnerable to privilege escalation (CVE-2026-5144), allowing a low-privileged user to gain administrator access on a WordPress Multisite network by manipulating group blog settings.
date: "2026-04-11T02:19:36Z"
severities:
  - critical
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

The BuddyPress Groupblog plugin, versions 1.9.3 and below, contains a critical privilege escalation vulnerability (CVE-2026-5144). This flaw allows authenticated attackers with minimal privileges (Subscriber or higher) to escalate privileges to Administrator on the main WordPress Multisite site. The vulnerability stems from a lack of authorization checks in the group blog settings handler. Specifically, the plugin improperly validates the `groupblog-blogid`, `default-member`, and…
