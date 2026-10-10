---
title: Privilege Escalation in FooSales POS for WooCommerce
slug: 2026-10-foosales-privilege-escalation
description: An authentication flaw in FooSales POS for WooCommerce (<= 1.43.0) allows authenticated users with cashier permissions to perform account takeover by modifying arbitrary user email addresses.
date: "2026-10-10T07:51:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:foosales:foosales_point_of_sale_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - FooSales
products:
  - FooSales – Point of Sale (POS) for WooCommerce (<= 1.43.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This makes it possible for authenticated attackers, with FooSales Cashier-level access and above, to change arbitrary user's email addresses, including administrators, and leverage that to reset the user's password and gain access to their account.
    confidence_band: high
cves:
  - id: CVE-2026-77183
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77183
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade FooSales plugin to version > 1.43.0
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability persists in versions up to 1.43.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade FooSales plugin to version > 1.43.0
      owner: IT Operations
      addresses: CVE-2026-77183
      evidence: NVD vulnerability report
---

The FooSales - Point of Sale (POS) for WooCommerce plugin for WordPress is vulnerable to privilege escalation via an insecure account detail update mechanism present in all versions up to, and including, 1.43.0. The vulnerability stems from the plugin's failure to properly validate a user's identity before allowing updates to sensitive account fields such as the email address. An authenticated attacker possessing at least FooSales Cashier-level access can exploit this flaw to overwrite the email address of any user in the WordPress system, including administrative accounts. By redirecting the email address, the attacker can subsequently trigger a standard WordPress password reset request, receive the reset token, and gain full control over the compromised account. This vulnerability poses a significant risk to e-commerce environments where site integrity and administrative access are critical.

## Attack Chain

1. Attacker authenticates to the WordPress site using a low-privilege account with FooSales Cashier permissions.
2. Attacker interacts with the FooSales plugin's account update functionality to modify profile information.
3. Attacker sends a crafted HTTP POST request to the server, targeting the vulnerable user-update endpoint with an arbitrary email address.
4. The plugin processes the request without sufficient identity validation, successfully updating the target administrator's email to an address controlled by the attacker.
5. Attacker navigates to the WordPress password reset page (wp-login.php?action=lostpassword) and requests a reset for the targeted administrator account.
6. The WordPress system sends the password reset token to the attacker-controlled email address.
7. Attacker completes the password reset process using the intercepted token.
8. Attacker logs in to the site as the administrator, achieving full control over the WooCommerce environment.

## Impact

Successful exploitation results in full administrative account takeover of the WordPress instance. This allows attackers to exfiltrate customer data, inject malicious scripts, manipulate payment configurations, and potentially deploy persistent backdoors within the WooCommerce environment. The vulnerability affects all users of the FooSales plugin version 1.43.0 and older.

## Recommendation

Prioritized actions for detection engineering and security teams:
- Update the FooSales - Point of Sale (POS) for WooCommerce plugin to the latest version (patch version > 1.43.0) immediately.
- Audit logs for unauthorized account detail modifications targeting administrative users, specifically monitoring for frequent changes to email addresses.
- Review WordPress application logs for suspicious activity originating from accounts with FooSales Cashier or similar roles.
- Disable account registration and tighten user privilege management until the patch is applied.
