---
title: Stored Cross-Site Scripting in Invisible Anti-Spam & CAPTCHA Plugin for WordPress
slug: 2026-08-wordpress-xss
description: An unauthenticated Stored Cross-Site Scripting (XSS) vulnerability in the Invisible Anti-Spam & CAPTCHA plugin (<= 5.1) allows attackers to inject malicious scripts via the action parameter in admin-ajax.php.
date: "2026-08-15T06:16:48Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - Invisible Anti-Spam & CAPTCHA — reCAPTCHA Alternative for All Forms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: The vulnerability stems from insufficient input sanitization and output escaping... allowing unauthenticated attackers to inject malicious scripts.
    confidence_band: high
cves:
  - id: CVE-2026-16145
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16145
rules:
  - title: Detect CVE-2026-16145 Exploitation - Stored XSS in WordPress Plugin
    description: Detects exploitation attempts targeting CVE-2026-16145 where an unauthenticated request to admin-ajax.php includes script-related tags in the action parameter.
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
    - action: Patch plugin to version > 5.1
      owner: IT Operations
      due: 24h
      evidence: Plugin version 5.1 is explicitly vulnerable.
    - action: Deploy WAF rule to monitor/block XSS patterns in admin-ajax.php
      owner: SOC
      due: 24h
      evidence: Rules defined in this brief.
---

The Invisible Anti-Spam & CAPTCHA plugin for WordPress, in versions 5.1 and earlier, contains a critical Stored Cross-Site Scripting (XSS) vulnerability. The flaw exists due to insufficient sanitization and escaping of the 'action' parameter when processed by the plugin's 'admin-ajax.php' handler. An attacker can submit unauthenticated HTTP requests to this endpoint, triggering the injection of arbitrary JavaScript into the application's database. Because the plugin auto-populates common form builder actions at activation, these entry points are publicly accessible without authentication. Successful exploitation allows for the execution of malicious scripts whenever an administrator or user views the affected page, potentially leading to session hijacking or unauthorized administrative actions.

## Impact

The vulnerability affects all sites utilizing the Invisible Anti-Spam & CAPTCHA plugin up to version 5.1. Successful exploitation enables unauthenticated attackers to execute arbitrary code in the context of the victim's browser session. In a WordPress environment, this frequently leads to full administrative account takeover, site defacement, or the injection of persistent malicious redirects and malware distribution scripts.

## Recommendation

- Update the Invisible Anti-Spam & CAPTCHA plugin to the latest available version beyond 5.1 immediately.
- Review web server logs for HTTP POST requests to admin-ajax.php containing suspicious characters (e.g., &lt;script>, alert(), or event handlers) within the 'action' parameter.
- Implement a Web Application Firewall (WAF) rule to validate input against the 'action' parameter on WordPress sites to block non-alphanumeric character injections.
