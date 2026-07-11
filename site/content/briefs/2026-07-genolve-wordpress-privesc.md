---
title: Vulnerability in Genolve WordPress Plugin Allows Privilege Escalation
slug: 2026-07-genolve-wordpress-privesc
description: A vulnerability in the Genolve AI image AI video generation plugin for WordPress, affecting versions up to and including 5.0.5, allows authenticated attackers with Contributor-level access to achieve privilege escalation due to a missing capability check in the `genolve_setOpt()` function, enabling them to modify arbitrary WordPress options such as enabling user registration and setting the default role to administrator.
date: "2026-07-11T09:17:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - privilege-escalation
  - vulnerability
vendors:
  - Genolve
  - WordPress
products:
  - Genolve - AI image AI video generation plugin for WordPress (<= 5.0.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This makes it possible for authenticated attackers, with Contributor-level access and above, to update arbitrary WordPress options, including enabling user registration and setting the default role to administrator, resulting in privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2026-1359
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1359
rules:
  - title: Detects CVE-2026-1359 Exploitation - Genolve Plugin Register Admin
    description: Detects CVE-2026-1359 exploitation attempts where an attacker leverages the Genolve plugin's missing capability check to enable user registration and set the default role to administrator.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-1359, has been identified in the Genolve - AI image AI video generation plugin for WordPress, affecting all versions up to and including 5.0.5. The flaw stems from a missing capability check within the `genolve_setOpt()` function, which is designed to set various plugin options. This oversight allows authenticated attackers with Contributor-level access or higher to bypass intended security controls and modify arbitrary WordPress options. Specifically, an attacker can leverage this vulnerability to enable user registration and set the default role for new users to 'administrator', directly leading to privilege escalation and potential site compromise. This vulnerability poses a significant risk to WordPress sites utilizing the affected Genolve plugin, as it allows less privileged users to gain full administrative control.

## Attack Chain

1. An authenticated attacker, possessing Contributor-level privileges or higher, logs into the vulnerable WordPress site.
2. The attacker crafts a malicious HTTP POST request targeting the WordPress AJAX endpoint (`/wp-admin/admin-ajax.php`).
3. The request includes parameters to invoke the `genolve_setOpt` action.
4. The attacker manipulates request parameters, specifically `option_name` and `option_value`, to enable `users_can_register` and set `default_role` to `administrator`.
5. Due to the missing capability check in the `genolve_setOpt()` function, the plugin processes these changes without proper authorization.
6. WordPress site options are updated, allowing new users to register with administrator privileges or an existing lower-privileged account to be elevated.
7. The attacker can then register a new administrator account, gaining full control over the WordPress site.

## Impact

Successful exploitation of CVE-2026-1359 grants authenticated attackers, even those with low-privileged Contributor roles, full administrative control over the affected WordPress site. This leads to complete compromise of the website, including data manipulation, defacement, content injection, and potential for further malicious activities such as malware distribution or phishing. The vulnerability has a CVSS v3.1 base score of 8.8, indicating a high severity risk. Organizations using the Genolve plugin for WordPress should consider all affected installations to be at risk of arbitrary option updates and subsequent privilege escalation if not patched.

## Recommendation

* Immediately update the Genolve - AI image AI video generation plugin to a version patched against CVE-2026-1359.
* Deploy the Sigma rules in this brief to your SIEM to detect attempts to exploit CVE-2026-1359 by monitoring webserver logs for suspicious `genolve_setOpt` calls.
* Monitor WordPress webserver access logs for anomalous requests to `/wp-admin/admin-ajax.php` containing `action=genolve_setOpt` combined with suspicious `option_name` and `option_value` parameters.
* Regularly review WordPress user accounts and their assigned roles to identify any unauthorized privilege escalations.
