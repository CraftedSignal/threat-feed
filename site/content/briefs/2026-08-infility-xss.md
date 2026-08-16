---
title: Stored Cross-Site Scripting in Infility Global WordPress Plugin
slug: 2026-08-infility-xss
description: The Infility Global WordPress plugin is vulnerable to Stored XSS via the /cf7_record endpoint, allowing unauthenticated attackers to execute arbitrary scripts in the context of authenticated users.
date: "2026-08-16T08:24:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - xss
  - wordpress
vendors:
  - Infility Global
products:
  - Infility Global plugin for WordPress (2.15.21)
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
    evidence: The injected payload executes for any logged-in user who visits the records page.
    confidence_band: high
cves:
  - id: CVE-2026-10734
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10734
rules:
  - title: Detects CVE-2026-10734 Exploitation - Stored XSS in Infility Global
    description: Detects exploitation attempts against the Infility Global plugin by identifying script-like payloads in POST requests to the /cf7_record endpoint.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Infility Global plugin to 2.15.22 or later
      owner: IT Operations
      due: 48h
      evidence: Plugin version 2.15.21 and earlier are vulnerable
    - action: Deploy Sigma detection rule to monitor for exploitation attempts
      owner: Detection Engineering
      due: 24h
      evidence: Plugin allows unauthenticated injection via /cf7_record
  mitigation_plan:
    - priority: immediate
      action: Block POST requests to /cf7_record containing script indicators
      owner: IT Operations
      addresses: CVE-2026-10734
      evidence: Insufficient input sanitization in /cf7_record endpoint
---

The Infility Global plugin for WordPress (versions 2.15.21 and earlier) contains a vulnerability due to insufficient input sanitization and output escaping. Specifically, the /cf7_record log endpoint allows unauthenticated attackers to inject malicious web scripts into the application's logging database. Because the /cf7_records viewer page is accessible to any authenticated user, including those with minimal Subscriber-level privileges, these injected scripts execute in the browser of any user who accesses the records interface. This flaw poses a significant risk to organizational WordPress instances by facilitating session hijacking, administrative account takeover, or the distribution of malicious redirects through legitimate site content.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of an authenticated user's session. This can lead to the theft of session cookies, modification of site content, or the execution of unauthorized administrative actions, effectively compromising the WordPress site and the integrity of data handled within the admin interface.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

- Update the Infility Global plugin for WordPress to version 2.15.22 or later to resolve CVE-2026-10734.
- Implement a Web Application Firewall (WAF) rule to inspect and block requests to the /cf7_record endpoint containing script tags or common JavaScript event handlers (e.g., &lt;script>, onerror, onload).
- Audit logs for the /cf7_record endpoint to identify any suspicious HTTP POST requests containing payload strings that deviate from the expected logging schema.
- Apply the Sigma rule below to identify potential exploitation attempts in web server access logs.
