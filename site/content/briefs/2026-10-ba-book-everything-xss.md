---
title: Stored Cross-Site Scripting in BA Book Everything Plugin
slug: 2026-10-ba-book-everything-xss
description: The BA Book Everything plugin for WordPress contains a Stored XSS vulnerability in the booking_service_qty parameter, allowing unauthenticated attackers to execute arbitrary scripts in the context of an administrator.
date: "2026-10-02T08:23:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ba_book_everything:ba_book_everything:*:*:*:*:*:*:*:*
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - BA Book Everything
products:
  - BA Book Everything (<= 1.8.28)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-102565
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102565
rules:
  - title: Detects CVE-2026-102565 Exploitation - Stored XSS in BA Book Everything
    description: Detects attempted exploitation of CVE-2026-102565 by identifying suspicious characters or script tags in the booking_service_qty parameter within POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Update BA Book Everything plugin to version 1.8.29 or newer.
      owner: IT Operations
      due: 24h
      evidence: Source document identifies versions <= 1.8.28 as vulnerable.
  hunt_leads:
    - lead: Search database for scripts stored in booking_service_qty column.
      technique_id: T1059.007
      data_needed:
        - WordPress database table contents
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Stored XSS vulnerability requires checking current records for malicious payloads.
  mitigation_plan:
    - priority: immediate
      action: Patch plugin.
      owner: IT Operations
      addresses: CVE-2026-102565
      evidence: NVD vulnerability disclosure.
---

The BA Book Everything plugin for WordPress, in all versions up to and including 1.8.28, is vulnerable to a Stored Cross-Site Scripting (XSS) attack. This vulnerability stems from insufficient input sanitization and output escaping of the 'booking_service_qty' parameter. An unauthenticated attacker can supply a malicious script payload through this parameter during the booking process. The script is then stored by the plugin and executed within the browser of an administrator or privileged user when they view the compromised order record within the WordPress dashboard. This vulnerability poses a significant risk as it allows for unauthorized actions performed under the context of an authenticated session, potentially leading to administrative account compromise or further internal exploitation.

## Attack Chain

1. Attacker identifies the target WordPress site using the BA Book Everything plugin.
2. Attacker crafts a malicious JavaScript payload intended for execution in an admin's browser.
3. Attacker initiates a booking request and sends a crafted POST request containing the script in the 'booking_service_qty' parameter.
4. The plugin fails to sanitize the input and stores the malicious script in the WordPress database associated with the order.
5. An administrator logs into the WordPress wp-admin dashboard to manage or review incoming orders.
6. The administrator accesses the compromised order record via the plugin's order management interface.
7. The browser renders the stored order details, triggering the execution of the attacker's script in the context of the administrator's authenticated session.
8. The attacker achieves their objective, such as creating a new admin user, exfiltrating session tokens, or modifying site configuration.

## Impact

Successful exploitation results in the execution of arbitrary code within the administrator's browser session. Given that the payload is viewed in the wp-admin management area, the attacker can hijack active sessions, perform administrative tasks, or inject further malicious content into the WordPress site, potentially affecting site integrity and the security of all registered users.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:

* Update the BA Book Everything plugin to version 1.8.29 or the latest available patched version immediately.
* Audit existing order records within the plugin for suspicious scripts, specifically looking for common HTML/JavaScript tags (e.g., &lt;script>, onerror, onload) in numeric fields.
* Monitor webserver logs for POST requests to the booking endpoint containing non-numeric characters within the 'booking_service_qty' parameter.
