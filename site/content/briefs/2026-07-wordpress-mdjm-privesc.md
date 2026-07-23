---
title: WordPress MDJM Event Management Plugin Privilege Escalation (CVE-2026-15017)
slug: 2026-07-wordpress-mdjm-privesc
description: An unauthenticated privilege escalation vulnerability (CVE-2026-15017) in the MDJM Event Management plugin for WordPress, affecting all versions up to 1.7.8.4, allows attackers to grant arbitrary MDJM capabilities to any registered WordPress role due to missing capability checks and nonce verification, ultimately enabling a low-privilege user to escalate to Administrator.
date: "2026-07-23T10:21:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - cve
  - web-application
vendors:
  - MDJM
  - WordPress
products:
  - MDJM Event Management plugin <= 1.7.8.4
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to grant arbitrary MDJM capabilities ... `MDJM_Permissions::init()` is registered on the public WordPress `init` hook without any authentication gate, meaning the role-manipulation endpoint is reachable without any prior login.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for unauthenticated attackers to grant arbitrary MDJM capabilities ... and subsequently leverage a subscriber-level account to escalate privileges to Administrator.
    confidence_band: high
cves:
  - id: CVE-2026-15017
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15017
---

The MDJM Event Management plugin for WordPress contains a critical privilege escalation vulnerability, CVE-2026-15017, affecting all versions up to and including 1.7.8.4. This flaw arises from insufficient capability checks and a lack of nonce verification within the `MDJM_Permissions::set_permissions()` and `MDJM_Employee_Manager::init()` functions. Additionally, the plugin fails to implement server-side allow-list validation on the `employee_roles[]` and `new_role` POST parameters. Attackers can exploit this by manipulating these parameters to assign arbitrary MDJM capabilities, such as `mdjm_employee` and `mdjm_employee_edit`, to any existing WordPress user role. The `MDJM_Permissions::init()` function, registered on the public WordPress `init` hook, allows this role manipulation endpoint to be accessed without requiring any prior authentication, making it possible for unauthenticated attackers to grant themselves elevated privileges. This vulnerability ultimately enables a low-privilege user, such as a subscriber, to escalate their account to Administrator privileges, granting full control over the affected WordPress site.

## Attack Chain

1. An unauthenticated attacker sends an HTTP POST request to a WordPress endpoint associated with the `MDJM_Permissions::init()` function.
2. The POST request includes specially crafted parameters, such as `employee_roles[]` and `new_role`, attempting to assign MDJM-specific capabilities like `mdjm_employee` or `mdjm_employee_edit` to a target WordPress user role (e.g., 'subscriber').
3. Due to missing capability checks, nonce verification, and server-side validation in the `MDJM_Permissions::set_permissions()` and `MDJM_Employee_Manager::init()` functions, the plugin processes these manipulated parameters via `mdjm_set_employee_role()` and `WP_User::set_role()`.
4. The target low-privilege account (e.g., a subscriber) is successfully updated with the newly assigned MDJM capabilities, effectively escalating its permissions within the plugin's scope.
5. The attacker, now operating with an account that possesses these elevated MDJM capabilities, may leverage other vulnerabilities or functionalities within the plugin or WordPress core.
6. The attacker uses their newly acquired capabilities to further escalate privileges, potentially by creating new administrative users, modifying existing user roles, or installing malicious plugins/themes.
7. The attacker achieves full Administrator privileges on the WordPress site, gaining complete control over its content, users, and underlying server if further exploitation is chained.

## Impact

Successful exploitation of CVE-2026-15017 allows an unauthenticated attacker to gain administrative control over the affected WordPress site. This provides full access to website content, user data, plugin settings, and server-side files if the WordPress installation is further exploited. Attackers can deface the site, inject malicious scripts (e.g., for drive-by downloads or phishing), exfiltrate sensitive information, or use the compromised server as a platform for further attacks. The severity is high due to the lack of authentication required for initial access and the complete compromise of the website's integrity and confidentiality that follows.

## Recommendation

* Patch CVE-2026-15017 immediately by updating the MDJM Event Management plugin to a patched version once released by the vendor.
* Review web server logs for suspicious HTTP POST requests directed at WordPress admin endpoints that attempt to manipulate `employee_roles[]` or `new_role` parameters, which could indicate exploitation attempts related to CVE-2026-15017.
