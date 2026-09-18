---
title: Booking Calendar Plugin Privilege Escalation via AJAX Parameter Injection
slug: 2026-09-booking-calendar-privilege-escalation
description: The Booking Calendar plugin for WordPress is vulnerable to privilege escalation (CVE-2026-92619) allowing authenticated Editors to modify arbitrary site settings and create administrative accounts.
date: "2026-09-18T08:04:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:booking_calendar:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - wordpress
  - web-application
vendors:
  - WordPress
products:
  - Booking Calendar (<= 11.8.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers with Editor-level access and above to escalate their privileges to Administrator by writing core WordPress options.
    confidence_band: high
cves:
  - id: CVE-2026-92619
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92619
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Booking Calendar plugin to 11.8.3 or later.
      owner: IT Operations
      due: 24h
      evidence: Source states all versions up to 11.8.2 are vulnerable.
  hunt_leads:
    - lead: Search web logs for POST requests to admin-ajax.php containing wpbc_ajax_option_save.
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation utilizes the wpbc_ajax_option_save AJAX action.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Booking Calendar to version 11.8.3.
      owner: IT Operations
      addresses: CVE-2026-92619
      evidence: Source identifies vulnerability in versions <= 11.8.2.
---

The Booking Calendar plugin for WordPress contains a critical privilege escalation vulnerability, assigned CVE-2026-92619, affecting all versions up to and including 11.8.2. The vulnerability resides in the `wpbc_ajax_option_save` AJAX action, specifically within the `handle_ajax_save()` function. The plugin fails to validate `data_name` parameters for unregistered options, causing the `get_option_policy()` function to return an empty policy object. This bypasses critical security checks such as `can_save`, `force_mode`, and `allowed_keys`. Furthermore, the nonce verification mechanism is flawed, as it accepts attacker-supplied nonce values and actions passed via POST parameters. Attackers can leverage this to modify sensitive WordPress core options - such as `default_role` and `users_can_register` - to facilitate the creation of unauthorized Administrator accounts.

## Attack Chain

1. Attacker obtains an active session with at least Editor-level privileges on the target WordPress site.
2. Attacker retrieves a valid nonce by requesting `admin-ajax.php?action=rest-nonce`.
3. Attacker crafts a POST request to `admin-ajax.php` with the action set to `wpbc_ajax_option_save`.
4. Attacker includes the retrieved nonce in the POST body to bypass the faulty verification check.
5. Attacker provides the `data_name` parameter as `default_role` and `data_value` as `administrator` to modify site settings.
6. Attacker sends a second request to update `users_can_register` to `1`.
7. Attacker navigates to the standard WordPress registration page and creates a new user account.
8. The new account is assigned the Administrator role due to the modified site settings.

## Impact

Successful exploitation results in full administrative control over the WordPress instance. This allows for unauthorized data access, complete site compromise, and the ability to execute further malicious actions within the affected environment. The flaw affects any installation of the Booking Calendar plugin versions 11.8.2 and earlier.

## Recommendation

Prioritized actions for security teams:
- Immediately upgrade the Booking Calendar plugin to version 11.8.3 or later, where the security policy checks have been hardened.
- Audit the `wp_options` table in the database for unexpected modifications to `default_role` or `users_can_register` settings.
- Review user accounts created or modified within the audit timeframe to identify unauthorized administrative access.
- Enable Web Application Firewall (WAF) logging for POST requests to `admin-ajax.php` to monitor for unusual `wpbc_ajax_option_save` payloads.
