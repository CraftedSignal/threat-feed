---
title: Unauthenticated Privilege Escalation in Blocksy Companion Plugin for WordPress
slug: 2026-10-blocksy-privilege-escalation
description: The Blocksy Companion WordPress plugin is vulnerable to unauthenticated privilege escalation, allowing attackers to create arbitrary vendor accounts by bypassing Dokan registration security checks.
date: "2026-10-10T05:33:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:creativethemes:blocksy_companion:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - WordPress
products:
  - Blocksy Companion (<= 2.1.58)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The Blocksy Companion plugin for WordPress is vulnerable to privilege escalation in versions up to, and including, 2.1.58.
    confidence_band: high
cves:
  - id: CVE-2026-107645
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107645
rules:
  - title: Detect CVE-2026-107645 - Blocksy Companion Unauthenticated Registration Attempt
    description: Detects exploitation of CVE-2026-107645 where an unauthenticated session performs a registration action via the Blocksy AJAX handler.
    platform: sigma
    severity: critical
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit WordPress installations for Blocksy Companion version <= 2.1.58
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-107645 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade Blocksy Companion to latest version
      owner: IT Operations
      addresses: CVE-2026-107645
      evidence: NVD vulnerability disclosure
---

The Blocksy Companion plugin for WordPress, in versions up to and including 2.1.58, contains a critical vulnerability (CVE-2026-107645) that enables unauthenticated privilege escalation. The vulnerability resides in the `implement_user_registration()` AJAX handler, which incorrectly disables the Dokan vendor-registration nonce check by executing `add_filter('dokan_register_nonce_check', '__return_false')`. 

By sending a specially crafted request to this endpoint, an unauthenticated attacker can supply an arbitrary `role` parameter to `wc_create_new_customer()` and `wc_set_customer_auth_cookie()`. This process ignores site-wide settings that may have disabled vendor registration, automatically creating and authenticating a user with 'seller' (vendor) privileges. This grants the attacker elevated publishing capabilities on the affected WordPress site, significantly expanding their control beyond that of a standard customer. Because this exploit operates via the public-facing AJAX handler, it is accessible to any remote, unauthenticated user, representing a high risk for sites running the vulnerable plugin configuration.

## Attack Chain

1. Attacker identifies a target WordPress site running the vulnerable Blocksy Companion plugin (version <= 2.1.58) with the Dokan plugin enabled.
2. Attacker crafts an HTTP POST request targeting the AJAX action associated with `implement_user_registration()`.
3. The request includes a malicious `role` parameter set to the 'seller' or 'vendor' role identifier.
4. The plugin's vulnerable AJAX handler executes, explicitly disabling the Dokan nonce validation filter.
5. The plugin invokes `wc_create_new_customer()` with the attacker-controlled role parameter.
6. The WordPress backend registers the new account and the `wc_set_customer_auth_cookie()` function is invoked.
7. The attacker receives an authentication cookie, allowing them to access the site with vendor-level publishing permissions.

## Impact

Successful exploitation allows unauthenticated users to gain unauthorized access to 'seller' or 'vendor' accounts on WordPress sites integrated with the Dokan plugin. This provides attackers with publishing capabilities, potentially leading to unauthorized content injection, cross-site scripting (XSS) vectors, or further exploitation of administrative functionality accessible to the vendor role. Any site utilizing Blocksy Companion and Dokan simultaneously is exposed to this risk.

## Recommendation

* Upgrade the Blocksy Companion plugin to the latest available version beyond 2.1.58 immediately.
* Monitor server access logs for anomalous `POST` requests to WordPress AJAX endpoints originating from unauthenticated sessions.
* Verify that Dokan vendor registration settings are explicitly managed by administrative policy rather than plugin-level overrides.
