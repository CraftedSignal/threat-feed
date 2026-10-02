---
title: Stored Cross-Site Scripting in The Newsletter Plugin for WordPress
slug: 2026-10-newsletter-xss
description: The Newsletter plugin for WordPress versions <= 9.4.0 is vulnerable to Stored XSS via the 'np1' parameter, allowing unauthenticated attackers to execute arbitrary scripts due to missing input sanitization and endpoint security controls.
date: "2026-10-02T08:24:11Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thenewsletterplugin:newsletter:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - WordPress
products:
  - The Newsletter – Send awesome emails from WordPress (<= 9.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page
    confidence_band: high
cves:
  - id: CVE-2026-96566
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96566
rules:
  - title: Detect CVE-2026-96566 Exploitation - Stored XSS Attempt via Subscription Endpoint
    description: Detects exploitation attempts against the Newsletter plugin where the 'np1' parameter contains script tags or HTML event handlers.
    platform: sigma
    severity: high
    tactics:
      - execution
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
    - IT Operations
  immediate_actions:
    - action: Update The Newsletter plugin to a patched version post-9.4.0
      owner: IT Operations
      due: 48h
      evidence: Plugin version 9.4.0 and earlier are vulnerable
  hunt_leads:
    - lead: Search logs for 'na=sa' and 'np1=' to identify potential previous exploitation attempts
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The endpoint (na=sa) is used for the subscription process where the exploit occurs
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to latest secure version
      owner: IT Operations
      addresses: CVE-2026-96566
      evidence: NVD vulnerability record
---

The Newsletter - Send awesome emails from WordPress plugin is affected by a Stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-96566) in all versions up to and including 9.4.0. The vulnerability exists due to insufficient sanitization and output escaping of the 'np1' custom field parameter. Because the plugin's subscription endpoint (na=sa) fails to implement nonce verification, capability checks, or CAPTCHA, unauthenticated attackers can successfully submit malicious payloads. An attacker can bypass standard WordPress email validation by injecting the '{profile_1}' placeholder into the local part of the email address, which the 'is_email()' function permits. Once the payload is stored, it executes in the browser of any user who views the affected page, leading to potential session hijacking or further administrative actions if an administrator views the data.

## Impact

Successful exploitation allows unauthenticated attackers to inject arbitrary web scripts into pages. This poses a high risk to WordPress installations by potentially facilitating account takeover or unauthorized actions if administrative users view the injected content. The vulnerability is widespread among sites utilizing this plugin for email management.

## Recommendation

Update the "The Newsletter - Send awesome emails from WordPress" plugin to a version released after 9.4.0 that contains the input sanitization patches. Monitor web server logs for HTTP POST requests to the subscription endpoint containing suspicious characters or script tags in the email or 'np1' parameters.

## Attack Chain

1. Attacker identifies a target WordPress site using the vulnerable plugin.
2. Attacker crafts a malicious payload containing JavaScript, wrapping it in an email-like structure.
3. Attacker uses the '{profile_1}' placeholder within the email field to bypass 'is_email()' validation.
4. Attacker includes the malicious script within the 'np1' custom field parameter.
5. Attacker submits a POST request to the 'na=sa' subscription endpoint.
6. The plugin improperly sanitizes the 'np1' input and stores it in the WordPress database.
7. A target user (e.g., an administrator) views the page where the stored script is rendered.
8. The malicious script executes in the victim's browser session.
