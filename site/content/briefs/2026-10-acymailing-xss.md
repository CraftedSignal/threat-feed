---
title: Stored Cross-Site Scripting in AcyMailing WordPress Plugin
slug: 2026-10-acymailing-xss
description: An unauthenticated stored XSS vulnerability in AcyMailing WordPress plugin version 11.1.0 and earlier allows attackers to inject malicious scripts via the customField[] parameter.
date: "2026-10-13T08:34:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:acymailing:acymailing:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - cms
  - vulnerability
vendors:
  - AcyMailing
products:
  - AcyMailing (<= 11.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can inject arbitrary web scripts via the customField[] parameter in the frontusers::subscribe endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-102562
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102562
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update AcyMailing to the version that resolves CVE-2026-102562
      owner: IT Operations
      due: 24h
      evidence: Source confirms plugin is vulnerable in versions <= 11.1.0
  mitigation_plan:
    - priority: immediate
      action: Block or filter malicious inputs in the customField parameter at the WAF level
      owner: SOC
      addresses: CVE-2026-102562
      evidence: Source identifies customField[] as the injection vector
---

The AcyMailing plugin for WordPress, in versions up to and including 11.1.0, contains a critical security vulnerability involving Stored Cross-Site Scripting (XSS). The issue stems from insufficient input sanitization within the acym_cleanVar() function. Specifically, the plugin's HTML tag stripping mechanism is flawed, as it only successfully sanitizes complete tags that include a closing bracket. Furthermore, the SubscriberInsertion::replaceUserInformation() method and the archive view template fail to perform proper HTML encoding when substituting stored subscriber data into emails and archive pages. An unauthenticated attacker can exploit this by submitting malicious scripts through the customField[] parameter in the frontusers::subscribe endpoint. These scripts remain dormant until a victim, such as a site administrator, views the poisoned subscriber profile via the online-archive URL or the Subscribers history interface, at which point the script executes within the context of the victim's session.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browser of an authenticated administrator or user. This can lead to session hijacking, unauthorized administrative actions within the WordPress dashboard, or the exfiltration of sensitive site data. The vulnerability affects all WordPress installations utilizing AcyMailing version 11.1.0 or lower.

## Recommendation

- Update the AcyMailing plugin to the latest version immediately to receive the patch for CVE-2026-102562.
- Implement a Web Application Firewall (WAF) to filter incoming HTTP requests containing suspicious script tags or JavaScript event handlers in the customField[] parameter.
- Audit the WordPress Subscribers history and archive pages for anomalous script tags if the site has been exposed to the internet while running vulnerable plugin versions.
