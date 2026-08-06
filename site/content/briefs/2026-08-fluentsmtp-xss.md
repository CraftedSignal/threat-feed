---
title: Stored XSS in FluentSMTP WordPress Plugin via Email Logs
slug: 2026-08-fluentsmtp-xss
description: An unauthenticated stored cross-site scripting vulnerability in the FluentSMTP WordPress plugin allows attackers to inject malicious scripts into email logs that execute in an administrator session.
date: "2026-08-06T05:21:52Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-vulnerability
  - wordpress
vendors:
  - FluentSMTP
products:
  - FluentSMTP – WP SMTP Plugin with Amazon SES, SendGrid, MailGun, Postmark, Google and Any SMTP Provider (<= 2.2.95)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: arbitrary web scripts in pages that will execute whenever a user accesses an injected page
    confidence_band: high
cves:
  - id: CVE-2026-16636
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16636
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Update FluentSMTP plugin to latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-16636 remediation
---

The FluentSMTP plugin for WordPress, specifically versions up to and including 2.2.95, contains a stored cross-site scripting (XSS) vulnerability. The issue stems from insufficient input sanitization and output escaping of the 'to.name' parameter when processing email logs through wp_mail() calls. Unauthenticated attackers can inject arbitrary web scripts into these logs, which are subsequently rendered in the WordPress administrative interface.

Crucially, while the primary list view of email logs utilizes an escapeHtml pipeline to prevent script execution, the detail view accessed via 'Prev' or 'Next' navigation controls fails to apply this security control. When an administrator navigates through email details, the injected payload triggers, allowing for arbitrary JavaScript execution in the context of the administrator's browser session. This vulnerability poses a significant risk to WordPress site integrity by enabling session hijacking or unauthorized administrative actions.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript within the administrative session of a WordPress site. This can lead to account takeover, the creation of rogue administrator accounts, or unauthorized modifications to site content or settings. Given the ubiquity of WordPress and the function of SMTP plugins, a large number of installations are potentially susceptible if they remain unpatched.

## Recommendation

* Update the FluentSMTP plugin to the latest version available beyond 2.2.95 to remediate the sanitization flaw.
* Monitor administrative access logs for unusual login patterns or the creation of new user accounts shortly after potential XSS trigger events.
* Audit WordPress logs for suspicious input contained within the 'to.name' fields of email logging tables.
* Deploy a Web Application Firewall (WAF) to detect and block common XSS payloads in request parameters.
