---
title: Stored XSS in Post SMTP WordPress Plugin
slug: 2026-10-post-smtp-xss
description: The Post SMTP plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the user_email parameter, allowing unauthenticated attackers to execute arbitrary scripts in the context of administrative log views.
date: "2026-10-06T08:53:50Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:post-smtp:post-smtp:*:*:*:*:*:wordpress:*:*
tags:
  - xss
  - web-application
  - wordpress
  - cve-2026-75962
vendors:
  - Post SMTP
products:
  - Post SMTP – Complete Email Deliverability and SMTP Solution with Email Logs, Alerts, Backup SMTP & Mobile App
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is exploitable without authentication on WordPress Multisite installations with public registration enabled
    confidence_band: high
cves:
  - id: CVE-2026-75962
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75962
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Audit WordPress site plugins and identify instances of Post SMTP version <= 4.0.1
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions <= 4.0.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade Post SMTP to the latest secure version (>= 4.0.2)
      owner: IT Operations
      addresses: CVE-2026-75962
      evidence: NVD vulnerability disclosure
---

The Post SMTP - Complete Email Deliverability and SMTP Solution plugin (up to version 4.0.1) contains a stored Cross-Site Scripting (XSS) vulnerability. The flaw originates from insufficient input sanitization and output escaping within the plugin's error handling mechanism. Specifically, on WordPress Multisite installations with public registration enabled, the plugin fails to properly handle numeric HTML character references in email addresses. When an attacker provides a maliciously crafted email address during registration, the plugin persists this data verbatim into the email logs via failed-send exception messages. Because the plugin does not properly escape this data when rendering the logs, the attacker-supplied script executes whenever an administrator or authorized user views the email logs. This vulnerability allows for unauthorized actions within the WordPress dashboard, potentially leading to privilege escalation or further compromise of the WordPress site.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the victim's browser session. This can be used to steal session cookies, perform unauthorized administrative actions, or redirect users. The impact is significant for WordPress Multisite administrators who rely on the Post SMTP plugin for email logging, as they are the primary targets when viewing the compromised logs.

## Recommendation

Prioritize patching the affected plugin to version 4.0.2 or later once available. If patching is not immediately feasible, restrict public access to registration pages on WordPress Multisite installations to mitigate the unauthenticated attack vector.
