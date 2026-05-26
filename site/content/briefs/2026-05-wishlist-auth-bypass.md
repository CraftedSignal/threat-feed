---
title: WishList Member WordPress Plugin Missing Authorization Leads to Privilege Escalation (CVE-2026-6895)
slug: 2026-05-wishlist-auth-bypass
description: The WishList Member plugin for WordPress is vulnerable to Missing Authorization, allowing attackers to obtain the REST API Secret Key and escalate privileges to administrator.
date: "2026-05-26T13:33:44Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - cve
vendors:
  - WordPress
products:
  - WishList Member plugin <= 3.30.1
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.006
    technique_name: Unprotected Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6895
    cvss: 8.8
    epss: 0.00039
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6895
rules:
  - title: Detect WishList Member export_settings Request
    description: Detects requests to the export_settings function in the WishList Member plugin, potentially indicating CVE-2026-6895 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548
    data_sources:
      - webserver
  - title: Detect WishList Member API Key Usage
    description: Detects usage of the WishList Member API Key, which may indicate exploitation after retrieval.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.006
    data_sources:
      - webserver
rules_count: 2
---

The WishList Member plugin for WordPress, versions up to and including 3.30.1, contains a missing authorization vulnerability. Specifically, the 'export_settings' function lacks proper capability checks. This flaw allows unauthenticated attackers to retrieve the REST API Secret Key via an AJAX JSON response. Obtaining this key enables the attacker to authenticate to the WishList Member API, which can then be leveraged to escalate privileges and create rogue administrator accounts. The vulnerability poses a significant risk to WordPress sites using the WishList Member plugin, potentially leading to complete site takeover.

## Attack Chain

1. An unauthenticated attacker sends a request to the WordPress server to trigger the 'export_settings' function in the WishList Member plugin via AJAX.
2. Due to missing authorization checks, the 'export_settings' function executes and returns the REST API Secret Key in the AJAX JSON response.
3. The attacker extracts the REST API Secret Key from the server's response.
4. The attacker uses the REST API Secret Key to authenticate to the WishList Member API.
5. The attacker uses the authenticated WishList Member API to create a new membership level.
6. The attacker assigns the administrator WordPress role to the newly created membership level.
7. The attacker registers a new user account and assigns it to the membership level created in the prior steps.
8. The attacker logs into the WordPress site using the newly created administrator-level user account, achieving complete site takeover.

## Impact

Successful exploitation of this vulnerability (CVE-2026-6895) allows an attacker to completely compromise a WordPress website. Attackers can create new administrative accounts, modify site content, install malicious plugins, and potentially gain access to sensitive data stored on the server. This can lead to significant reputational damage, financial loss, and potential legal consequences for the website owner.

## Recommendation

*   Upgrade the WishList Member plugin to the latest version to patch CVE-2026-6895.
*   Monitor web server logs for requests to the `export_settings` function in the WishList Member plugin using the Sigma rule `Detect WishList Member export_settings Request`.
*   Review existing WordPress user accounts and membership levels for any unauthorized or suspicious entries after patching, and investigate potential exploitation.
