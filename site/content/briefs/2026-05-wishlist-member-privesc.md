---
title: WishList Member Plugin Privilege Escalation via Missing Authorization (CVE-2026-6419)
slug: 2026-05-wishlist-member-privesc
description: The WishList Member plugin for WordPress is vulnerable to privilege escalation (CVE-2026-6419) due to a missing capability and nonce check in the ajax_get_screen() function, allowing authenticated attackers with subscriber-level access to retrieve the plugin's REST API Secret Key and create administrator accounts, leading to complete site takeover.
date: "2026-05-26T13:33:27Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - privilege-escalation
  - wordpress
  - plugin
  - CVE-2026-6419
vendors:
  - WordPress
products:
  - WishList Member plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6419
    cvss: 8.8
    epss: 0.00039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6419
rules:
  - title: Detect WishList Member API Key Retrieval (CVE-2026-6419)
    description: Detects CVE-2026-6419 exploitation — An authenticated user attempts to retrieve the WishList Member REST API key by exploiting the ajax_get_screen function.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect WishList Member Admin Account Creation via API (CVE-2026-6419)
    description: Detects CVE-2026-6419 post-exploitation — Creation of a new administrator-level user via the WishList Member API after obtaining the REST API Secret Key.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

The WishList Member plugin for WordPress, versions up to and including 3.30.1, is vulnerable to a privilege escalation vulnerability (CVE-2026-6419). The vulnerability stems from a missing capability and nonce check in the `ajax_get_screen()` function. This flaw allows authenticated attackers with subscriber-level access (or higher) to supply an arbitrary admin screen identifier via the `data[url]` parameter. This leads the plugin to load and execute the administrative API configuration template without proper authorization. A successful exploit allows the attacker to retrieve the plugin's plaintext REST API Secret Key. This key can then be used to authenticate to the WishList Member API and create new membership levels with the administrator WordPress role. Finally, the attacker can register an arbitrary administrator-level user account, resulting in a complete site takeover.

## Attack Chain

1.  An attacker logs into a WordPress site with a valid, low-privileged account (e.g., Subscriber).
2.  The attacker crafts a malicious AJAX request targeting the `/wp-admin/admin-ajax.php` endpoint.
3.  The crafted request includes the `action=wishlistmember_get_screen` parameter, triggering the vulnerable `ajax_get_screen()` function within the WishList Member plugin.
4.  The request includes a `data[url]` parameter containing a crafted string pointing to an administrative screen related to the plugin's API configuration. This bypasses the missing capability and nonce check.
5.  The `ajax_get_screen()` function executes the administrative API configuration template, exposing the plaintext REST API Secret Key in the response.
6.  The attacker extracts the REST API Secret Key from the AJAX JSON response.
7.  The attacker uses the obtained REST API Secret Key to authenticate to the WishList Member API and create a new membership level associated with the WordPress administrator role.
8.  Finally, the attacker registers a new WordPress user account and assigns it to the newly created administrator-level membership, granting themselves complete control of the WordPress site.

## Impact

Successful exploitation of CVE-2026-6419 allows a low-privileged attacker to gain complete control of the affected WordPress site. This can lead to data breaches, defacement, malware distribution, and denial of service. The vulnerability affects all WordPress sites using the WishList Member plugin versions 3.30.1 and below. The potential number of affected sites is estimated to be in the tens of thousands based on plugin download statistics.

## Recommendation

*   Upgrade the WishList Member plugin to the latest version to patch CVE-2026-6419.
*   Deploy the Sigma rule "Detect WishList Member API Key Retrieval (CVE-2026-6419)" to detect attempts to exploit this vulnerability by monitoring for requests to `/wp-admin/admin-ajax.php` with the `wishlistmember_get_screen` action and suspicious `data[url]` parameters.
*   Monitor WordPress access logs for unusual AJAX requests originating from low-privileged user accounts, and investigate any suspicious activity.
