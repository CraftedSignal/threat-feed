---
title: Stored XSS in Real Estate Manager WordPress Plugin via CVE-2026-96667
slug: 2026-10-real-estate-manager-xss
description: The Real Estate Manager plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) due to insufficient input sanitization of the first_name parameter, allowing unauthenticated attackers to bypass reCAPTCHA and execute arbitrary scripts.
date: "2026-10-10T07:51:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:real_estate_manager_property_listing_and_agent_management:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - xss
  - web-application
  - cve-2026-96667
vendors:
  - WordPress
products:
  - Real Estate Manager – Property Listing and Agent Management (<= 7.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-96667
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96667
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Real Estate Manager plugin to version > 7.3
      owner: IT Operations
      due: 24h
      evidence: Plugin version 7.3 is explicitly cited as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Patch plugin or disable functionality until update is applied
      owner: IT Operations
      addresses: CVE-2026-96667
      evidence: Source documentation identifies version 7.3 and below as vulnerable.
---

The Real Estate Manager - Property Listing and Agent Management plugin for WordPress, in versions up to and including 7.3, contains a critical security flaw identified as CVE-2026-96667. The vulnerability manifests as a Stored Cross-Site Scripting (XSS) condition caused by improper input sanitization and output escaping within the 'first_name' parameter. Furthermore, the plugin's reCAPTCHA implementation is flawed, as it only validates the request if the 'g-recaptcha-response' parameter is present; an attacker can completely bypass this check by simply omitting the parameter from their HTTP request. This vulnerability allows an unauthenticated attacker to inject arbitrary malicious scripts, which will execute within the browser context of any user who views the affected page, leading to potential session hijacking or unauthorized administrative actions.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the context of a victim's session. This may result in session theft, unauthorized account modifications, or redirection of users to malicious sites. The scope of impact is limited to sites running the vulnerable Real Estate Manager plugin version 7.3 or lower, which is widely utilized in the real estate sector.

## Recommendation

* Update the Real Estate Manager - Property Listing and Agent Management plugin to a version released after 7.3 immediately.
* Monitor server logs for HTTP POST requests to the plugin's submission endpoints containing script tags or JavaScript event handlers in the 'first_name' field.
* Implement a Web Application Firewall (WAF) rule to inspect input fields for common XSS payloads, specifically targeting the 'first_name' parameter.
