---
title: AcyMailing Plugin Privilege Escalation Vulnerability (CVE-2026-3614)
slug: 2026-04-acymailing-privesc
description: The AcyMailing plugin for WordPress is vulnerable to privilege escalation (CVE-2026-3614), allowing authenticated attackers with subscriber-level access to gain administrative privileges.
date: "2026-04-16T06:16:18Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - wordpress
  - privilege-escalation
  - acymailing
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-3614
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3614
rules:
  - title: AcyMailing Unauthorized AJAX Access Attempt
    description: Detects attempts to access the acymailing_router AJAX handler without administrator privileges, indicating a potential privilege escalation attempt (CVE-2026-3614).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1212
    data_sources:
      - webserver
      - linux
  - title: AcyMailing Autologin Enabled
    description: Detects when the autologin feature is enabled in AcyMailing, which is a prerequisite for exploiting CVE-2026-3614. Requires AcyMailing logging.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The AcyMailing plugin for WordPress, a popular email marketing tool, contains a critical privilege escalation vulnerability, tracked as CVE-2026-3614. Affecting versions 9.11.0 through 10.8.1, the vulnerability stems from a missing capability check on the `wp_ajax_acymailing_router` AJAX handler. This oversight allows authenticated attackers with minimal privileges (Subscriber level or higher) to bypass access controls intended to restrict access to administrative functions. Successful exploitation of this flaw allows attackers to perform actions reserved for administrators, including modifying configuration settings, enabling autologin features, and ultimately, compromising the entire WordPress installation. This is a critical vulnerability due to the widespread use of AcyMailing and the potential for complete site takeover.

## Attack Chain

1.  Attacker gains subscriber-level access to the WordPress site (e.g., through registration or compromised credentials).
2.  Attacker crafts a malicious AJAX request targeting the `wp_ajax_acymailing_router` endpoint. This request attempts to access admin-only controllers without proper authentication.
3.  Due to the missing capability check, the server processes the request, granting the attacker access to restricted administrative functions within AcyMailing.
4.  The attacker enables the autologin feature within AcyMailing's configuration, using the exposed administrative controller.
5.  The attacker creates a new AcyMailing subscriber.  Crucially, the attacker injects a malicious `cms_id` value into the subscriber's data. This `cms_id` is crafted to point to the WordPress user account they wish to impersonate (e.g., an administrator account).
6.  The attacker retrieves the autologin URL generated for the newly created (and malicious) subscriber.
7.  The attacker accesses the autologin URL.
8.  The AcyMailing plugin, configured with the now-enabled autologin feature, authenticates the attacker as the user specified by the injected `cms_id`, granting them full administrative access to the WordPress site.

## Impact

Successful exploitation of CVE-2026-3614 allows an attacker to escalate privileges from a subscriber to an administrator. This grants the attacker complete control over the WordPress website, including the ability to modify content, install malicious plugins, create new administrator accounts, and potentially compromise the underlying server. This vulnerability impacts any WordPress site running a vulnerable version of the AcyMailing plugin (9.11.0 through 10.8.1). The severity is critical due to the ease of exploitation and the potential for complete system compromise.

## Recommendation

*   Immediately update the AcyMailing plugin to the latest version (greater than 10.8.1) to patch CVE-2026-3614.
*   Deploy the Sigma rule "AcyMailing Unauthorized AJAX Access Attempt" to detect attempts to exploit the vulnerability by monitoring for access to the `wp_ajax_acymailing_router` endpoint from non-administrator users.
*   Monitor web server logs for suspicious POST requests to `/wp-admin/admin-ajax.php` with the `action=acymailing_router` parameter, as this is the entry point for exploiting CVE-2026-3614.
