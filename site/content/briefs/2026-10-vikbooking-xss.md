---
title: Stored Cross-Site Scripting in VikBooking WordPress Plugin
slug: 2026-10-vikbooking-xss
description: The VikBooking Hotel Booking Engine & PMS plugin for WordPress up to version 1.8.15 contains a Stored XSS vulnerability in the 'attachments[name]' parameter that allows unauthenticated attackers to inject malicious scripts.
date: "2026-10-10T07:52:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:vikwp:vikbooking:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - xss
vendors:
  - VikWP
products:
  - VikBooking Hotel Booking Engine & PMS (<= 1.8.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The VikBooking Hotel Booking Engine & PMS plugin for WordPress is vulnerable to Stored Cross-Site Scripting via 'attachments[name]' Parameter.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-95684
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-95684
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Update VikBooking plugin to version > 1.8.15
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade VikBooking Hotel Booking Engine & PMS to version 1.8.16 or later
      owner: IT Operations
      addresses: CVE-2026-95684
      evidence: Source identified vulnerability in 1.8.15 and below
---

The VikBooking Hotel Booking Engine & PMS plugin for WordPress, in all versions up to and including 1.8.15, is vulnerable to a Stored Cross-Site Scripting (XSS) vulnerability. This flaw exists due to insufficient input sanitization and output escaping on the 'attachments[name]' parameter. Unauthenticated attackers can exploit this vulnerability to inject arbitrary web scripts into the application. When a victim, such as an administrator or another user, accesses the page where the malicious script is stored, the browser executes the script in the context of the user session. This can lead to unauthorized administrative actions, session hijacking, or redirection to malicious sites. Because the plugin is used for hotel booking management, this vulnerability poses a high risk to businesses managing guest and administrative data within the WordPress dashboard.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a legitimate user's browser session. In a WordPress environment, this typically results in account takeover, unauthorized modification of plugin settings, or exfiltration of sensitive booking data. The target scope includes any WordPress instance running vulnerable versions of VikBooking.

## Recommendation

1. Immediately update the VikBooking Hotel Booking Engine & PMS plugin to a version beyond 1.8.15.
2. Audit WordPress dashboard access logs for suspicious POST requests targeting plugin attachment endpoints.
3. Implement a Web Application Firewall (WAF) rule to inspect input parameters containing HTML or script tags directed at the plugin's attachment functionality.
