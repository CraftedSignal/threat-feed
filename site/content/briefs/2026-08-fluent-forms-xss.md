---
title: Stored XSS in Fluent Forms WordPress Plugin via Notification Smartcodes
slug: 2026-08-fluent-forms-xss
description: An unauthenticated Stored Cross-Site Scripting (XSS) vulnerability in Fluent Forms versions up to 6.2.11 allows attackers to inject malicious scripts that execute in the context of administrative users viewing submission logs.
date: "2026-08-13T08:54:48Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Fluent Forms
products:
  - Fluent Forms (<= 6.2.11)
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
    evidence: inject arbitrary web scripts that execute in the browser of an administrator
    confidence_band: high
cves:
  - id: CVE-2026-18146
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18146
---

The Fluent Forms - Customizable Contact Forms, Survey, Quiz, & Conversational Form Builder plugin for WordPress is affected by a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-18146). The vulnerability stems from inadequate input sanitization and output escaping when processing Notification Smartcode values. Unauthenticated attackers can exploit this by submitting forms containing malicious payloads designed to be interpreted as Smartcodes. If an administrator or a user with entry-viewing permissions accesses the Submission Logs within the WordPress admin dashboard, the injected script executes in their browser session. This vulnerability impacts all versions of the plugin up to and including 6.2.11.

## Impact

Successful exploitation leads to the execution of arbitrary JavaScript within the administrative context of the WordPress dashboard. This can be used to perform actions on behalf of the administrator, such as creating new administrative accounts, modifying plugin configurations, or redirecting users to malicious sites, potentially leading to a full site compromise.

## Recommendation

* Update the Fluent Forms WordPress plugin to the latest version immediately to remediate CVE-2026-18146.
* Audit WordPress administrative logs for unusual activity originating from the plugin's submission management interface.
* Review all configured form notifications to identify potential misuse of Smartcode fields that may be reachable by unauthenticated form submitters.
