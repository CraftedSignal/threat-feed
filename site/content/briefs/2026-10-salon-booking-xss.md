---
title: Stored Cross-Site Scripting in Salon Booking System Plugin
slug: 2026-10-salon-booking-xss
description: An unauthenticated Stored XSS vulnerability in the Salon Booking System WordPress plugin allows attackers to inject malicious scripts into checkout fields.
date: "2026-10-16T06:26:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:salonbookingsystem:salon_booking_system:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - xss
  - wordpress
  - cve-2026-109232
vendors:
  - Salon Booking System
products:
  - Salon Booking System – Appointment Booking for Salons, Barbershops & Spas (<= 10.31.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An unauthenticated attacker can inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-109232
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109232
rules:
  - title: Detect CVE-2026-109232 Exploitation - Malicious Payload in Booking Checkout
    description: Detects exploitation of CVE-2026-109232 by identifying script-like patterns in POST requests targeting the Salon Booking System checkout parameter.
    platform: sigma
    severity: high
    tactics:
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
    - Detection Engineering
  immediate_actions:
    - action: Review WordPress site configurations for Salon Booking System plugins and ensure they are patched to latest version
      owner: SOC
      due: 48h
      evidence: Plugin version vulnerability (<= 10.31.9)
  hunt_leads:
    - lead: Search logs for POST requests containing <script or onload strings in parameters starting with sln
      technique_id: T1059.007
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source document identifies parameter-based injection vector
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin or disable custom checkout fields of type Html/File
      owner: IT Operations
      addresses: CVE-2026-109232
      evidence: Source documentation identifies field types as exploitation prerequisite
---

The Salon Booking System - Appointment Booking for Salons, Barbershops & Spas plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'sln[&lt;checkout-field-key>]' parameter. This vulnerability affects all versions up to and including 10.31.9. The flaw exists due to insufficient input sanitization and output escaping of user-provided data within custom checkout fields. An unauthenticated attacker can exploit this by injecting arbitrary web scripts into pages that utilize these fields. Successful exploitation occurs when a site administrator has configured at least one custom checkout field of type Html or File. When a user subsequently accesses the affected page, the injected script executes in the user's browser context, potentially allowing session hijacking, unauthorized actions, or further compromise of the victim's interaction with the site.

## Impact

The vulnerability poses a significant risk to WordPress sites utilizing the affected plugin for booking management. Successful exploitation allows for the execution of arbitrary JavaScript in the context of site users or administrators. This could lead to the theft of session cookies, administrative account takeover, or redirection of users to malicious third-party sites. Given the plugin's function as a booking system, high-traffic sites managing customer data are primary targets.

## Recommendation

* Immediately update the Salon Booking System - Appointment Booking for Salons, Barbershops & Spas plugin to a version beyond 10.31.9, once a patch is available.
* Audit existing custom checkout fields configured within the plugin to identify and remove any suspicious content or unexpected scripts.
* Implement or strengthen Content Security Policy (CSP) headers on WordPress sites to mitigate the impact of injected malicious scripts.
* Monitor web access logs for anomalous POST requests directed at plugin-specific booking endpoints that contain script-like characters or payloads.
