---
title: WordPress Profile Builder Pro Plugin PHP Object Injection Vulnerability (CVE-2026-7647)
slug: 2024-01-wordpress-profile-builder-rce
description: An unauthenticated PHP Object Injection vulnerability exists in the Profile Builder Pro WordPress plugin (versions up to 3.14.5) due to the insecure use of `maybe_unserialize()` on the 'args' POST parameter in the `wppb_request_users_pins_action_callback()` AJAX handler, potentially leading to arbitrary code execution.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - php-object-injection
  - wordpress
  - plugin
  - rce
vendors:
  - WordPress
products:
  - Profile Builder Pro plugin
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-7647
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7647
rules:
  - title: Detect Profile Builder Pro PHP Object Injection Attempt
    description: Detects attempts to exploit the PHP Object Injection vulnerability (CVE-2026-7647) in the Profile Builder Pro plugin by monitoring POST requests to the vulnerable AJAX endpoint with suspicious serialized data.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Profile Builder Pro wppb_request_users_pins_action_callback AJAX Call
    description: Detects calls to the wppb_request_users_pins_action_callback AJAX action in WordPress, potentially indicating exploitation attempts against Profile Builder Pro.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Profile Builder Pro plugin for WordPress is susceptible to a critical PHP Object Injection vulnerability (CVE-2026-7647) affecting all versions up to and including 3.14.5. This flaw stems from the plugin's use of the `maybe_unserialize()` function on the attacker-controlled `args` POST parameter passed to the `wppb_request_users_pins_action_callback()` AJAX handler. Critically, this handler lacks nonce verification, input validation, and type checking, making it accessible to unauthenticated users via both `wp_ajax_` and `wp_ajax_nopriv_` hooks. Successful exploitation allows remote, unauthenticated attackers to inject arbitrary PHP objects into the application's memory space, potentially leading to remote code execution depending on available classes and application configuration. The vulnerability was published on 2026-05-02.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site running a vulnerable version (<= 3.14.5) of the Profile Builder Pro plugin.
2.  The attacker crafts a malicious HTTP POST request targeting the WordPress AJAX endpoint (`/wp-admin/admin-ajax.php`).
3.  The POST request includes the `action` parameter set to `wppb_request_users_pins_action_callback`.
4.  The POST request includes the `args` parameter containing a serialized PHP object designed to trigger arbitrary code execution upon deserialization.
5.  The WordPress server receives the request and invokes the `wppb_request_users_pins_action_callback()` function.
6.  The vulnerable function calls `maybe_unserialize()` on the attacker-controlled `args` parameter without proper sanitization or validation.
7.  The malicious PHP object is deserialized and injected into the application's memory space.
8.  The injected object's methods and properties are triggered, leading to arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary PHP code on the target WordPress server. This can lead to complete system compromise, including data theft, website defacement, and the installation of backdoors for persistent access. Given the widespread use of WordPress and the Profile Builder Pro plugin, a large number of websites are potentially at risk until the plugin is updated.

## Recommendation

*   Upgrade the Profile Builder Pro plugin to the latest available version to patch CVE-2026-7647.
*   Deploy the provided Sigma rule `Detect Profile Builder Pro PHP Object Injection Attempt` to detect exploitation attempts targeting the vulnerable AJAX endpoint.
*   Monitor web server logs for POST requests to `/wp-admin/admin-ajax.php` with the `action` parameter set to `wppb_request_users_pins_action_callback` and suspicious serialized data in the `args` parameter.
