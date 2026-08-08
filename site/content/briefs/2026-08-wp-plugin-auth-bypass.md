---
title: Authorization Bypass in AI Copilot - Content Generator WordPress Plugin
slug: 2026-08-wp-plugin-auth-bypass
description: An authorization bypass vulnerability in the AI Copilot - Content Generator WordPress plugin allows unauthenticated attackers to create administrator accounts and achieve full site takeover via malformed workflow execution.
date: "2026-08-08T07:37:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application
  - wordpress
  - cve-2026-14526
  - auth-bypass
vendors:
  - WordPress
products:
  - AI Copilot – Content Generator (<= 1.5.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078.002
    technique_name: 'Valid Accounts: Domain Accounts'
    evidence: Unauthenticated attackers can leverage a public-facing nonce and the plugin's workflow feature to execute the wp_create_user function.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1133
    technique_name: External Remote Services
    evidence: This makes it possible for unauthenticated attackers to create a new administrator-level user account and achieve full site takeover.
    confidence_band: high
cves:
  - id: CVE-2026-14526
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14526
rules:
  - title: Detects CVE-2026-14526 Exploitation - Unauthorized Account Creation
    description: Detects exploitation attempts where an unauthenticated attacker calls the WordPress wp_create_user function via the AI Copilot plugin workflow engine.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1078.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or disable AI Copilot - Content Generator plugin
      owner: IT Operations
      due: 24h
      evidence: Plugin vulnerable in versions <= 1.5.6
  hunt_leads:
    - lead: Search logs for wp_create_user and role=administrator in URI strings
      technique_id: T1078
      data_needed:
        - Webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this as the mechanism for exploitation
  mitigation_plan:
    - priority: immediate
      action: Update plugin to version > 1.5.6
      owner: IT Operations
      addresses: CVE-2026-14526
      evidence: NVD advisory
---

The AI Copilot - Content Generator plugin for WordPress (versions 1.5.6 and earlier) contains a critical authorization bypass vulnerability. The plugin fails to adequately verify user permissions during the execution of workflow actions. Because the application exposes a required nonce in the `WAIC_DATA.waicNonce` JavaScript object on any page rendering the `[aiwu-form]` shortcode or public chatbot, the nonce check effectively fails as an authorization control. An unauthenticated attacker can capture this nonce and craft a request to the plugin's workflow engine, injecting a `wp_create_user` action node with `role=administrator`. This allows the creation of unauthorized administrative accounts, resulting in full site compromise. Defenders must monitor for unauthorized user creation events and identify the presence of this plugin on their WordPress instances.

## Attack Chain

1. Attacker navigates to a public-facing WordPress page that utilizes the `[aiwu-form]` shortcode or the plugin's public chatbot interface.
2. Attacker inspects the source code of the page to locate the `WAIC_DATA.waicNonce` value within the rendered JavaScript.
3. Attacker constructs a malicious workflow request intended for the plugin's backend endpoint.
4. Attacker inserts a `wp_create_user` action node into the workflow, configuring the payload to set the `role` parameter to `administrator`.
5. Attacker transmits the crafted request to the WordPress site, including the extracted `waic-nonce` to bypass the authentication check.
6. The plugin processes the workflow engine request, executing the `wp_create_user` function with the attacker-supplied parameters.
7. A new administrative user is created within the WordPress database.
8. Attacker authenticates with the newly created account to establish persistent, full-access administrative control over the site.

## Impact

Successful exploitation results in full site takeover. An attacker can gain persistent administrative access, leading to the exfiltration of sensitive site data, modification of site content, redirection of users to malicious infrastructure, or use of the server as a node for further attacks.

## Recommendation

* Immediately update the "AI Copilot - Content Generator" plugin to a version later than 1.5.6 to patch the authorization bypass vulnerability (CVE-2026-14526).
* If the update cannot be applied, disable the plugin and remove any pages containing the `[aiwu-form]` shortcode or the public chatbot interface.
* Audit the WordPress database for suspicious administrative accounts created by unknown sources, specifically monitoring user registration logs for entries generated via the plugin's backend logic.
* Review web server logs for HTTP POST requests to plugin-specific workflow endpoints that contain `wp_create_user` payloads.
