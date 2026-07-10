---
title: CVE-2026-15293 - WP Business Intelligence Lite Plugin Authorization Bypass Leading to Privilege Escalation
slug: 2026-07-wp-business-intelligence-lite-auth-bypass
description: The WP Business Intelligence Lite plugin for WordPress contains an authorization bypass vulnerability (CVE-2026-15293) affecting all versions up to and including 3.2.0, allowing authenticated attackers with Subscriber-level access or higher to modify stored SQL queries which can lead to arbitrary SQL execution and privilege escalation when an administrator views the modified query.
date: "2026-07-10T05:22:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin-vulnerability
  - authorization-bypass
  - privilege-escalation
  - web-application
  - cve
vendors:
  - WordPress
products:
  - WP Business Intelligence Lite plugin (<= 3.2.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to modify stored SQL queries, which can lead to privilege escalation via arbitrary SQL execution when the modified query is viewed by an administrator.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
    evidence: which can lead to privilege escalation via arbitrary SQL execution when the modified query is viewed by an administrator.
    confidence_band: med
cves:
  - id: CVE-2026-15293
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15293
---

A critical authorization bypass vulnerability, identified as CVE-2026-15293, exists within the WP Business Intelligence Lite plugin for WordPress, impacting all versions up to and including 3.2.0. This flaw stems from inadequate authorization checks, enabling authenticated attackers with as little as Subscriber-level privileges to modify existing stored SQL queries within the plugin. The core issue arises when an administrator subsequently accesses or views these maliciously altered queries, triggering the execution of arbitrary SQL commands under the administrator's context. This ultimately leads to privilege escalation, allowing the attacker to potentially gain full control over the WordPress database and underlying system. The vulnerability poses a significant risk to WordPress sites utilizing this plugin, potentially leading to data compromise, website defacement, or complete system takeover.

## Attack Chain

1. An authenticated attacker gains access to a WordPress instance with at least Subscriber-level privileges.
2. The attacker leverages the authorization bypass vulnerability within the WP Business Intelligence Lite plugin to gain unauthorized access to functionality designed to modify stored SQL queries.
3. The attacker crafts and injects malicious SQL commands into an existing stored query within the plugin's configuration.
4. The attacker waits for an administrator to log into the WordPress dashboard and navigate to a section that displays or executes the compromised stored SQL query.
5. When the administrator views the modified query, the vulnerable plugin executes the injected malicious SQL commands within the context of the administrator's high-privilege session.
6. The arbitrary SQL execution grants the attacker elevated privileges, potentially leading to full control over the WordPress database and the ability to perform actions such as creating new administrative users or exfiltrating sensitive data.

## Impact

The successful exploitation of CVE-2026-15293 grants attackers arbitrary SQL execution capabilities, leading to privilege escalation on the affected WordPress site. This can result in severe consequences, including full compromise of the database, creation of unauthorized administrator accounts, exfiltration of sensitive user data, defacement of the website, or injection of malicious code. Organizations running the vulnerable WP Business Intelligence Lite plugin risk significant data breaches, reputational damage, and potential regulatory fines due to the elevated access gained by attackers.

## Recommendation

* Immediately update the WP Business Intelligence Lite plugin to a version patched against CVE-2026-15293. If an update is not available, disable or uninstall the plugin.
