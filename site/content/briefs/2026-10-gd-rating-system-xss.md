---
title: Stored Cross-Site Scripting in GD Rating System WordPress Plugin
slug: 2026-10-gd-rating-system-xss
description: An unauthenticated Stored Cross-Site Scripting vulnerability in the GD Rating System plugin for WordPress allows attackers to execute arbitrary JavaScript via the gdrts_live_handler AJAX action by bypassing a trivially accessible nonce.
date: "2026-10-03T06:54:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:gd_rating_system_project:gd_rating_system:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - WordPress
products:
  - GD Rating System (<= 3.7.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The GD Rating System plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'title' and 'url' Render Args in gdrts_live_handler AJAX
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-93430
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93430
rules:
  - title: Detects CVE-2026-93430 Exploitation - POST to gdrts_live_handler
    description: Detects exploitation attempts against the GD Rating System plugin by monitoring for POST requests to the AJAX handler containing common XSS vectors.
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
    - action: Update GD Rating System plugin beyond 3.7.1
      owner: IT Operations
      due: 48h
      evidence: Plugin version 3.7.1 and earlier are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Deactivate GD Rating System plugin
      owner: IT Operations
      addresses: CVE-2026-93430
      evidence: CVE-2026-93430 vulnerability
---

The GD Rating System plugin for WordPress, in all versions up to and including 3.7.1, is susceptible to a Stored Cross-Site Scripting (XSS) vulnerability. The flaw exists within the gdrts_live_handler AJAX action, which fails to adequately sanitize the 'title' and 'url' parameters before processing. An attacker can leverage this to inject arbitrary malicious web scripts into the application. While the vulnerable AJAX endpoint is intended to be protected by a nonce, the plugin exposes this nonce publicly within a JSON block inside the HTML source of every page rendering a rating component. This exposure renders the nonce ineffective as an authentication or authorization control, allowing unauthenticated attackers to trigger the injection successfully. The vulnerability poses a significant risk as it allows for the execution of scripts in the context of victim users' browsers, potentially leading to session hijacking, defacement, or unauthorized actions performed on behalf of authenticated administrators.

## Attack Chain

1. Attacker visits a public page on the WordPress site that utilizes the GD Rating System plugin.
2. Attacker parses the HTML source code of the page to locate the script tag with the class 'gdrts-rating-data'.
3. Attacker extracts the valid nonce required for the AJAX action from the JSON block found within the script tag.
4. Attacker constructs an HTTP POST request targeting the /wp-admin/admin-ajax.php endpoint.
5. Attacker includes the 'action' parameter set to 'gdrts_live_handler' and includes the stolen nonce in the request.
6. Attacker injects malicious JavaScript payloads into the 'title' or 'url' parameters of the POST request.
7. The plugin processes the request and persists the malicious payload into the site database without proper sanitization.
8. The payload executes in the browser of any user (including administrators) who visits the page where the rating item is displayed.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's session. This can lead to the theft of session cookies, administrative account takeover, redirecting users to malicious sites, or performing unauthorized actions within the WordPress dashboard if an administrator views the injected content.

## Recommendation

Prioritized actions for security teams:
- Update the GD Rating System plugin to a version beyond 3.7.1 immediately to patch the sanitization logic.
- If a patch is unavailable, deactivate the GD Rating System plugin to prevent exploitation of the gdrts_live_handler endpoint.
- Monitor web application firewall logs for HTTP POST requests to 'admin-ajax.php' containing unusual strings in the 'title' or 'url' fields, specifically those attempting to inject script tags or event handlers.
- Deploy the Sigma rule below to detect attempts to access the vulnerable AJAX handler if feasible.
