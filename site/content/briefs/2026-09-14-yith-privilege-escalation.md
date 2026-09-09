---
title: Privilege Escalation in YITH WooCommerce Waitlist Premium Plugin
slug: 2026-09-14-yith-privilege-escalation
description: Authenticated attackers can exploit a missing capability check and nonce validation in the YITH WooCommerce Waitlist Premium plugin to elevate privileges to administrator.
date: "2026-09-09T10:49:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yith:woocommerce_waitlist_premium:*:*:*:*:*:wordpress:*:*
tags:
  - privilege-escalation
  - wordpress
  - web-application-attack
vendors:
  - YITH
products:
  - WooCommerce Waitlist Premium (<= 3.35.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The YITH WooCommerce Waitlist Premium plugin for WordPress is vulnerable to Privilege Escalation... making it possible for authenticated attackers... to elevate their privileges to that of an administrator.
    confidence_band: high
cves:
  - id: CVE-2026-14359
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14359
rules:
  - title: Detect CVE-2026-14359 Exploitation - Unauthorized Privilege Escalation via AJAX
    description: Detects exploitation of CVE-2026-14359 by monitoring for POST requests to the YITH WooCommerce Waitlist AJAX action that include user role manipulation keywords.
    platform: sigma
    severity: high
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
    - action: Upgrade YITH WooCommerce Waitlist Premium to version 3.35.1 or later
      owner: IT Operations
      due: 24h
      evidence: Source states versions up to 3.35.0 are vulnerable.
  hunt_leads:
    - lead: Search web logs for POST requests to wp-admin/admin-ajax.php containing yith_wcwtl_add_user
      technique_id: T1068
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability relies on the add_user_in_waiting_list function mapped to the wp_ajax_yith_wcwtl_add_user action.
  mitigation_plan:
    - priority: immediate
      action: Disable the affected plugin until a verified update is deployed
      owner: IT Operations
      addresses: CVE-2026-14359
      evidence: Plugin vulnerability requires immediate patching or removal.
---

The YITH WooCommerce Waitlist Premium plugin for WordPress (versions up to and including 3.35.0) contains a critical privilege escalation vulnerability, CVE-2026-14359. The flaw originates from the add_user_in_waiting_list() function, which is registered to the wp_ajax_yith_wcwtl_add_user hook. This function fails to implement necessary security controls, specifically missing capability checks and nonce verification.

Furthermore, the function insecurely utilizes parse_str() and extract() to process variables from the $_POST['params'] array. An authenticated attacker, such as a subscriber, can supply maliciously crafted input to this endpoint, allowing them to manipulate the wp_create_user() and $user->set_role() calls. By injecting specific parameters, the attacker can force the application to create a new user account with administrative privileges, granting them full control over the compromised WordPress installation.

## Impact

Successful exploitation allows any authenticated user (e.g., a subscriber) to gain full administrative access to the WordPress site. This leads to complete site takeover, potential data exfiltration of customer information, unauthorized modification of site content, and potential persistent backdoor installation.

## Recommendation

1. Patch immediately by upgrading the YITH WooCommerce Waitlist Premium plugin to version 3.35.1 or later.
2. Audit current WordPress administrative users for accounts created via the wp_ajax_yith_wcwtl_add_user endpoint to identify potential past compromise.
3. Deploy the web application firewall (WAF) rule to block POST requests to the vulnerable AJAX action that contain suspicious parameter payloads attempting to set user roles.
