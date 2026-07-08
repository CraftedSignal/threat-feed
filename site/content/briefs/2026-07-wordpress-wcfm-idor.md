---
title: 'CVE-2026-3688: WordPress WCFM Membership Plugin Insecure Direct Object Reference'
slug: 2026-07-wordpress-wcfm-idor
description: Authenticated attackers with vendor-level access can exploit an Insecure Direct Object Reference (IDOR) vulnerability (CVE-2026-3688) in the WCFM Membership - WooCommerce Memberships for Multivendor Marketplace plugin for WordPress to change any user's role to 'wcfm_vendor' by manipulating membership plans, leading to unauthorized privilege escalation.
date: "2026-07-08T12:18:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - web
  - vulnerability
  - idor
  - privilege-escalation
vendors:
  - WCLovers
  - WordPress
  - WooCommerce
products:
  - WCFM Membership – WooCommerce Memberships for Multivendor Marketplace < 2.11.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authenticated attackers, with vendor level access and above
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers... to change any user's role to 'wcfm_vendor' by changing their membership plan.
    confidence_band: high
cves:
  - id: CVE-2026-3688
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3688
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/8a934ccd-9330-4585-9994-838940d24980?source=cve
---

A critical Insecure Direct Object Reference (IDOR) vulnerability, tracked as CVE-2026-3688, has been identified in the WCFM Membership - WooCommerce Memberships for Multivendor Marketplace plugin for WordPress, affecting all versions up to and including 2.11.10. This flaw stems from insufficient validation of user permissions within the 'wcfmvm_membership_change' AJAX action, failing to confirm if an authenticated user is authorized to modify other users' roles or membership plans. Exploitation allows an authenticated attacker, holding at least vendor-level privileges, to arbitrarily alter any user's role within the marketplace to 'wcfm_vendor'. This can lead to unauthorized account takeover, disruption of marketplace operations, and potential financial impact by granting malicious actors control over other vendor accounts.

## Attack Chain

1. An attacker obtains valid authentication credentials for a WordPress account with at least vendor-level access on a site running the vulnerable WCFM Membership plugin.
2. The attacker logs into the WordPress site, establishing an authenticated session.
3. The attacker crafts a malicious HTTP POST request targeting the `/wp-admin/admin-ajax.php` endpoint.
4. The crafted request includes the `action=wcfmvm_membership_change` parameter along with specific data identifying a target user and a desired membership plan corresponding to the 'wcfm_vendor' role.
5. Due to the Insecure Direct Object Reference vulnerability (CVE-2026-3688), the plugin fails to properly validate whether the authenticated attacker has permission to modify the specified target user's membership.
6. The plugin processes the illicit request, updating the target user's membership plan.
7. The target user's role within the WCFM marketplace is consequently changed to 'wcfm_vendor'.
8. The attacker achieves unauthorized privilege escalation, gaining control over another user's vendor account.

## Impact

This vulnerability carries a CVSS v3.1 Base Score of 8.1 (High), indicating significant impact. Successful exploitation by an authenticated attacker, even with basic vendor access, allows them to arbitrarily change the role of any other user to 'wcfm_vendor'. This directly translates to unauthorized privilege escalation, potentially granting attackers control over other legitimate vendor accounts within the marketplace. Such control can lead to disruption of normal marketplace operations, fraudulent transactions, data manipulation, reputation damage, and financial losses for the affected organization and its users.

## Recommendation

* Immediately update the "WCFM Membership - WooCommerce Memberships for Multivendor Marketplace" plugin to a patched version greater than 2.11.10 to remediate CVE-2026-3688.
* Review web server access logs for any suspicious POST requests to `/wp-admin/admin-ajax.php` with `action=wcfmvm_membership_change` that originate from unexpected IP addresses or accounts during the period the vulnerable plugin was active.
* Examine WordPress user roles for any unauthorized changes to 'wcfm_vendor' during the period the vulnerable plugin was active.
