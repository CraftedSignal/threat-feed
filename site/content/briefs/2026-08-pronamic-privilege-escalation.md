---
title: Privilege Escalation in Pronamic Pay WordPress Plugin
slug: 2026-08-pronamic-privilege-escalation
description: The Pronamic Pay plugin for WordPress is vulnerable to privilege escalation via the unvalidated update of user roles in the Gravity Forms integration.
date: "2026-08-01T09:50:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - privilege-escalation
  - web-application
vendors:
  - Pronamic
products:
  - Pronamic Pay (<= 10.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Subscriber-level access and above, to escalate their own WordPress account to Administrator by tampering with the role field value in a form submission.
    confidence_band: high
cves:
  - id: CVE-2026-16635
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16635
---

The Pronamic Pay plugin for WordPress, in versions up to and including 10.1.0, contains a critical privilege escalation vulnerability identified as CVE-2026-16635. The flaw resides within the `maybe_update_user_role()` function, which processes data from Gravity Forms payment feeds. Specifically, the plugin takes user-controlled input from a Gravity Forms field and passes it directly to the `WP_User::set_role()` WordPress core function without performing any server-side validation, role allowlisting, or capability checks. 

For exploitation to occur, an administrator must have previously configured a Pronamic Pay payment feed with the 'Update User Role' feature enabled and mapped to a specific form field. An attacker with a low-privileged account, such as a Subscriber, can then submit a crafted request via the associated Gravity Forms instance, manipulating the mapped field value to set their own account role to 'Administrator'. Because the plugin performs no permission verification before calling the role update, this allows for immediate privilege escalation, granting the attacker full administrative control over the WordPress site.

## Impact

Successful exploitation allows an authenticated user to gain Administrator privileges on the affected WordPress site. This results in complete system compromise, enabling the attacker to install arbitrary plugins, modify site content, extract database information, or execute further malicious activities. The vulnerability impacts all WordPress installations utilizing Pronamic Pay up to version 10.1.0, posing a significant risk to organizations relying on this plugin for payment processing and user management.

## Recommendation

* Update the Pronamic Pay plugin to the latest version immediately to remediate CVE-2026-16635.
* Audit WordPress user accounts for unauthorized changes in administrative roles.
* Review all Gravity Forms payment feed configurations to ensure the 'Update User Role' feature is disabled if not strictly required for business operations.
* Monitor WordPress logs for unusual 'profile_update' or 'user_role_updated' actions associated with low-privileged user accounts.
