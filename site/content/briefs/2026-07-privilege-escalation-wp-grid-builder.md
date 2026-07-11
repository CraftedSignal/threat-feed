---
title: CVE-2026-13756 - Privilege Escalation in WP Grid Builder WordPress Plugin
slug: 2026-07-privilege-escalation-wp-grid-builder
description: An authenticated attacker with Subscriber-level access or higher can exploit a missing authorization and meta key validation vulnerability in the WP Grid Builder plugin for WordPress (versions up to and including 2.3.3) by sending a crafted nested array payload to the `/wp-json/wpgb/v2/metadata` REST endpoint, which allows them to update their own `wp_capabilities` user meta and effectively escalate their privileges to Administrator level.
date: "2026-07-11T02:17:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - wordpress
  - plugin
  - cve
vendors:
  - WP Grid Builder
  - WordPress
products:
  - WP Grid Builder plugin <= 2.3.3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to elevate their privileges to Administrator by updating their own `wp_capabilities` user meta with a crafted nested array payload.
    confidence_band: high
cves:
  - id: CVE-2026-13756
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13756
rules:
  - title: Detects CVE-2026-13756 Exploitation Attempt - WP Grid Builder Privilege Escalation
    description: Detects HTTP POST requests to the vulnerable WP Grid Builder metadata REST endpoint, which could indicate an attempt to exploit CVE-2026-13756 for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

A critical privilege escalation vulnerability, tracked as CVE-2026-13756, exists in all versions up to and including 2.3.3 of the WP Grid Builder plugin for WordPress. This flaw stems from inadequate authorization checks and meta key validation within the `update()` handler of the `/wp-json/wpgb/v2/metadata` REST endpoint. Exploitation allows authenticated attackers, even those with low-privileged Subscriber accounts, to elevate their user privileges to Administrator level. By sending a specially crafted nested array payload that manipulates the `wp_capabilities` user meta, an attacker can bypass security controls and gain full control over the affected WordPress site. This vulnerability poses a significant risk to the integrity and security of WordPress installations utilizing the WP Grid Builder plugin, potentially leading to complete website compromise, data manipulation, or further malicious activity.

## Attack Chain

1. An authenticated attacker, possessing at least Subscriber-level privileges on a WordPress site, identifies the presence of the vulnerable WP Grid Builder plugin (version 2.3.3 or earlier).
2. The attacker crafts a specific JSON payload designed to modify their `wp_capabilities` user meta, embedding a nested array structure within it.
3. The attacker then sends an HTTP POST request targeting the `/wp-json/wpgb/v2/metadata` REST endpoint of the vulnerable WordPress site.
4. The crafted JSON payload, containing the desired `wp_capabilities` modification, is included in the body of this HTTP POST request.
5. Due to missing authorization and insufficient meta key validation in the plugin's `update()` handler, the malicious request is processed without proper scrutiny.
6. The plugin's functionality updates the attacker's `wp_capabilities` user meta with the values provided in the crafted payload.
7. As a result, the attacker's user account is granted Administrator-level privileges, effectively escalating their access.
8. The attacker now possesses full administrative control over the WordPress site, enabling further malicious actions.

## Impact

Successful exploitation of CVE-2026-13756 leads directly to full administrative control over the compromised WordPress instance. This allows attackers to perform any action an administrator can, including installing malicious plugins, modifying theme files, injecting malware, defacing the website, stealing sensitive data, or redirecting site visitors to malicious domains. While no specific victim counts or targeted sectors are available, any WordPress site running the vulnerable WP Grid Builder plugin is at risk of complete compromise, potentially impacting business operations, user trust, and data privacy. The high CVSS score of 8.8 reflects the critical nature of this privilege escalation.

## Recommendation

* Immediately update the WP Grid Builder plugin to the latest patched version to remediate CVE-2026-13756.
* Deploy the Sigma rule provided in this brief to your SIEM to detect exploitation attempts targeting the `/wp-json/wpgb/v2/metadata` REST endpoint.
* Regularly review webserver logs (specifically for the `/wp-json/wpgb/v2/metadata` endpoint) for unusual POST requests, particularly those from low-privileged users, and tune the detection rule to reduce false positives.
