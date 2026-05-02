---
title: WordPress WCFM Plugin Vulnerable to IDOR Leading to Account Deletion
slug: 2026-05-wordpress-wcfm-idor
description: The WCFM plugin for WordPress is vulnerable to an Insecure Direct Object Reference (IDOR) that allows authenticated attackers with Vendor-level access or higher to delete arbitrary users, including administrators.
date: "2026-05-02T14:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - idor
  - wordpress
  - woocommerce
  - account-deletion
vendors:
  - WordPress
products:
  - WCFM – Frontend Manager for WooCommerce along with Bookings Subscription Listings Compatible plugin <= 6.7.25
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1213
    technique_name: Insecure Direct Object Reference
cves:
  - id: CVE-2026-2554
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-2554
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/21e397a4-0b32-4b13-a46b-c465acea0796?source=cve
rules:
  - title: Detect WCFM User Deletion Attempt via IDOR
    description: Detects attempts to delete users via the wcfm_delete_wcfm_customer function with a suspicious customerid, indicating a potential IDOR vulnerability exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
  - title: Detect WCFM User Deletion of Administrator Account
    description: Detects attempts to delete the administrator user account via the wcfm_delete_wcfm_customer function, indicating a potential IDOR vulnerability exploitation with high impact.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WCFM – Frontend Manager for WooCommerce along with Bookings Subscription Listings Compatible plugin, a popular WordPress plugin, is affected by an Insecure Direct Object Reference (IDOR) vulnerability. This flaw, present in versions up to and including 6.7.25, stems from a lack of proper validation on the `customerid` parameter within the `wcfm_delete_wcfm_customer` function. An attacker with Vendor-level privileges or higher can exploit this vulnerability to delete any user account on the WordPress instance, including those with administrative rights. This can lead to complete compromise of the affected website.

## Attack Chain

1.  An attacker authenticates to the WordPress site with Vendor-level access or higher.
2.  The attacker crafts a malicious HTTP request targeting the `wcfm_delete_wcfm_customer` function.
3.  The attacker includes the `customerid` parameter in the request, setting its value to the ID of the target user account they wish to delete.
4.  Due to the missing validation on the `customerid` parameter, the application directly uses the provided ID to locate the user account.
5.  The `wcfm_delete_wcfm_customer` function proceeds to delete the user account identified by the attacker-supplied `customerid`.
6.  The targeted user account is successfully deleted from the WordPress instance.
7.  If the deleted user account was an administrator, the attacker can effectively take control of the website.

## Impact

Successful exploitation of this IDOR vulnerability allows an attacker to delete arbitrary user accounts, including those with administrative privileges. This can lead to a complete compromise of the affected WordPress website. An attacker could then deface the website, steal sensitive data, or use it to launch further attacks. Due to the popularity of the plugin, a large number of WooCommerce stores are potentially affected.

## Recommendation

*   Apply the latest available patch or upgrade to a version of the WCFM plugin greater than 6.7.25 to remediate CVE-2026-2554.
*   Monitor web server logs for suspicious requests to `wcfm_delete_wcfm_customer` with unusual `customerid` values, using the Sigma rule provided below.
*   Implement input validation on the `customerid` parameter within the `wcfm_delete_wcfm_customer` function to prevent arbitrary user deletion.
