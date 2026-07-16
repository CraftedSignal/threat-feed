---
title: WPFunnels Plugin Privilege Escalation via Arbitrary Option Update
slug: 2026-07-wpfunnels-privilege-escalation
description: Authenticated attackers with the `wpf_manage_funnels` capability can exploit CVE-2026-15103, a privilege escalation vulnerability in the `update_settings()` REST callback of the WPFunnels - Funnel Builder for WooCommerce with Checkout & One Click Upsell plugin for WordPress (versions up to and including 3.12.8), allowing them to gain full site administrator access by injecting a crafted role definition into the `wp_user_roles` option.
date: "2026-07-16T09:20:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - wordpress
  - plugin
vendors:
  - WPFunnels
  - WordPress
products:
  - WPFunnels – Funnel Builder for WooCommerce with Checkout & One Click Upsell plugin (<= 3.12.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with the `wpf_manage_funnels` capability and above to elevate their privileges to administrator by writing a crafted role definition containing arbitrary capabilities into the `wp_user_roles` option, thereby granting any WordPress role full site administrator access.
    confidence_band: high
cves:
  - id: CVE-2026-15103
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15103
rules:
  - title: Detects CVE-2026-15103 Exploitation - WPFunnels Privilege Escalation Attempt
    description: Detects attempts to exploit CVE-2026-15103 by targeting the `wp_user_roles` option via the WPFunnels plugin's `update_settings` REST API endpoint, indicating a privilege escalation attempt.
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

CVE-2026-15103 describes a critical privilege escalation vulnerability affecting all versions up to, and including, 3.12.8 of the "WPFunnels - Funnel Builder for WooCommerce with Checkout & One Click Upsell" plugin for WordPress. The flaw resides in the `update_settings()` REST callback, which fails to properly validate the `group_id` path parameter. This allows authenticated attackers with the `wpf_manage_funnels` capability (typically assigned to the custom "Funnel Manager" role) to manipulate the `wp_user_roles` option. By injecting a specially crafted role definition, attackers can grant arbitrary capabilities, including full site administrator access, to any WordPress role. This vulnerability presents a significant risk to affected WordPress sites, as it allows users with limited privileges to escalate their access to administrator level, potentially leading to full site compromise.

## Attack Chain

1. An authenticated attacker, possessing at least the `wpf_manage_funnels` capability, accesses the WordPress site.
2. The attacker crafts a malicious request targeting the `/wp-json/wp-funnels/v1/settings/update-settings/{group_id}` REST endpoint.
3. In this request, the attacker sets the `{group_id}` path parameter to `wp_user_roles`.
4. The attacker includes a payload in the request body containing a crafted role definition that grants administrator capabilities to an existing WordPress user role, or creates a new role with elevated privileges.
5. The vulnerable `update_settings()` REST callback, failing to validate `group_id` against an allowlist, passes `wp_user_roles` directly to `get_option()` and `update_option()`.
6. The crafted role definition is written into the `wp_user_roles` option in the WordPress database, effectively modifying user roles and capabilities.
7. The attacker, or another user, can then assume the modified role, gaining full site administrator access and control over the WordPress instance.

## Impact

A successful exploitation of CVE-2026-15103 directly leads to full site compromise, as attackers can elevate their privileges to that of an administrator. This grants them complete control over the WordPress instance, including the ability to install malicious plugins, themes, modify site content, exfiltrate sensitive data, or inject web shells. While no specific victim numbers or sectors are mentioned, any WordPress site running the vulnerable WPFunnels plugin without appropriate patches is at risk. The financial and reputational damage from a complete site takeover can be substantial.

## Recommendation

* Patch CVE-2026-15103 immediately by updating the "WPFunnels - Funnel Builder for WooCommerce with Checkout & One Click Upsell" plugin to version 3.12.9 or newer on all affected WordPress installations.
* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect suspicious REST API calls attempting to modify the `wp_user_roles` option.
* Review webserver access logs for anomalous `POST` requests to the `/wp-json/wp-funnels/v1/settings/update-settings/wp_user_roles` endpoint.
