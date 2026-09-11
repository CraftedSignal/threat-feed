---
title: SQL Injection in Sticky Chat Widget WordPress Plugin
slug: 2026-09-sticky-chat-sqli
description: The Sticky Chat Widget plugin for WordPress (<= 1.4.2) is vulnerable to unauthenticated SQL injection via the 'scw_save_form_data' AJAX action, allowing potential exfiltration of sensitive database information.
date: "2026-09-11T05:11:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:sticky_chat_widget:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sqli
  - wordpress
vendors:
  - WordPress
products:
  - Sticky Chat Widget (<= 1.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries.
    confidence_band: high
cves:
  - id: CVE-2026-15462
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15462
rules:
  - title: Detects CVE-2026-15462 Exploitation - SQL Injection in Sticky Chat Widget
    description: Detects attempts to exploit the SQL injection vulnerability in the Sticky Chat Widget plugin via the scw_save_form_data action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit web server logs for requests matching the detection rule signature.
      owner: SOC
      due: 24h
      evidence: Source describes exploitation via scw_save_form_data action.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Sticky Chat Widget to a version greater than 1.4.2.
      owner: IT Operations
      addresses: CVE-2026-15462
      evidence: Plugin version <= 1.4.2 is vulnerable.
---

The Sticky Chat Widget plugin for WordPress, in versions up to and including 1.4.2, contains a critical SQL injection vulnerability. The flaw resides in the 'scw_save_form_data' AJAX action, where the 'scw_form_fields' parameter array keys are processed by the 'save_form_data()' function. Because the plugin passes these attacker-supplied POST array keys to '$wpdb->insert()' without adequate sanitization, it is possible for an attacker to inject backtick characters. These characters allow the attacker to break out of the intended column-identifier list and introduce raw SQL commands into the database query. Furthermore, the use of 'filter_input()' bypasses standard WordPress 'wp_magic_quotes()' protections. Because the 'widget_id' validation loop is skipped when no valid ID is provided, an unauthenticated attacker can trigger this code path to perform unauthorized database operations, potentially resulting in the exfiltration of sensitive data.

## Attack Chain

1. Attacker identifies a WordPress site running Sticky Chat Widget version 1.4.2 or lower.
2. Attacker crafts an HTTP POST request targeting the 'admin-ajax.php' endpoint.
3. The request includes the 'action' parameter set to 'scw_save_form_data'.
4. The attacker provides a malicious payload within the 'scw_form_fields' parameter using crafted array keys containing backticks.
5. The 'save_form_data()' function receives the input, bypassing the 'wp_magic_quotes()' filter via 'filter_input()'.
6. The plugin logic skips the 'widget_id' validation loop, confirming the '$isValid' flag as true.
7. The unsanitized input is passed to '$wpdb->insert()', allowing the injected SQL to break the query structure.
8. Final Objective: Database exfiltration through manipulated SQL queries.

## Impact

Successful exploitation allows an unauthenticated remote attacker to execute arbitrary SQL commands against the WordPress database. This can lead to the unauthorized retrieval of sensitive information, such as user credentials, site configuration details, or other private data stored within the WordPress database tables.

## Recommendation

Prioritize the update of the Sticky Chat Widget plugin to the latest available version beyond 1.4.2. As of this report, no specific fixed version is provided, so security teams should monitor the WordPress plugin repository for updates or disable the plugin if an update is not immediately available. For detection teams, monitor web server logs for suspicious AJAX requests targeting 'admin-ajax.php' with 'scw_save_form_data' as the action parameter, specifically looking for unusual characters like backticks within the POST data.
