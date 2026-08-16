---
title: Stored XSS Vulnerability in Bookly WordPress Plugin
slug: 2026-08-bookly-xss
description: The Bookly WordPress plugin contains a stored XSS vulnerability via the bookly_speed_up_update_addons AJAX action, allowing unauthenticated attackers to inject malicious scripts that execute in an administrator's browser.
date: "2026-08-16T08:24:45Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Bookly
products:
  - Online Scheduling and Appointment Booking System – Bookly
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-13424
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13424
rules:
  - title: Detect CVE-2026-13424 Exploitation - Bookly AJAX XSS
    description: Detects unauthenticated POST requests to the vulnerable Bookly AJAX action that may contain malicious scripts.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rule to monitor and block malicious AJAX requests
      owner: SOC
      due: 24h
      evidence: Plugin is vulnerable via unauthenticated AJAX call
  mitigation_plan:
    - priority: immediate
      action: Monitor for plugin updates and patch immediately
      owner: IT Operations
      addresses: CVE-2026-13424
      evidence: Source confirms vulnerability in version 27.7 and below
---

The Bookly WordPress plugin (versions 27.7 and earlier) is vulnerable to a stored Cross-Site Scripting (XSS) attack. This vulnerability arises from insufficient input sanitization and output escaping within the 'bookly_speed_up_update_addons' AJAX action. Because this action is registered as 'wp_ajax_nopriv', it is accessible to unauthenticated attackers.

An attacker can submit a crafted AJAX request to the plugin that lacks a valid signature. The plugin stores the malicious input within the 'bookly_log' table in the 'details' column. The payload executes in the browser of any administrator who navigates to the 'Diagnostics → Logs' page within the WordPress dashboard. This facilitates administrative session hijacking, unauthorized configuration changes, or the execution of arbitrary JavaScript within the context of the WordPress admin panel. Defenders should prioritize updating to the patched version once available and monitor logs for anomalous AJAX requests to the vulnerable endpoint.

## Attack Chain

1. Attacker identifies a WordPress site running a vulnerable version of the Bookly plugin (<= 27.7).
2. Attacker crafts an HTTP POST request targeting the 'wp-admin/admin-ajax.php' endpoint.
3. Attacker sets the 'action' parameter to 'bookly_speed_up_update_addons'.
4. Attacker inserts a JavaScript payload into the request parameters intended for the 'details' field.
5. The plugin fails to validate the request signature and writes the unsanitized payload into the 'bookly_log' table.
6. An administrator accesses the 'Diagnostics → Logs' page in the WordPress admin dashboard.
7. The browser renders the stored JavaScript payload, executing it in the administrator's security context.
8. Attacker leverages the hijacked administrative session to further compromise the WordPress site.

## Impact

Successful exploitation allows unauthenticated attackers to achieve Stored XSS against WordPress administrators. This can lead to full administrative account takeover, site defacement, unauthorized plugin installation, or redirection of site visitors to malicious infrastructure, significantly impacting the integrity and availability of the web application.

## Recommendation

- Update the Bookly plugin to the latest version immediately once a patch is provided by the vendor.
- Implement WAF rules to detect and block POST requests to 'admin-ajax.php' containing the 'action=bookly_speed_up_update_addons' parameter and suspicious script-related characters.
- Deploy the Sigma rule below to monitor for exploitation attempts targeting the vulnerable AJAX action.
