---
title: Stored XSS via Authentication Bypass in Amelia WordPress Plugin
slug: 2026-08-amelia-xss
description: An unauthenticated stored Cross-Site Scripting (XSS) vulnerability in the Amelia WordPress plugin allows attackers to inject malicious scripts into appointment bookings, which execute in an administrator's browser context.
date: "2026-08-28T09:13:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - xss
  - wordpress
  - vulnerability
vendors:
  - TMS Outsource
products:
  - Amelia
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The AddBookingCommand explicitly skips nonce verification, allowing unauthenticated users to submit booking data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts that will execute when an administrator accesses the Calendar page.
    confidence_band: med
cves:
  - id: CVE-2026-6286
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6286
---

The Booking for Appointments and Events Calendar (Amelia) plugin for WordPress (versions 2.2 and below) is vulnerable to Stored Cross-Site Scripting (XSS) due to an authentication bypass in the plugin's command processing. The AddBookingCommand class fails to perform nonce verification, allowing unauthenticated users to submit booking data. Although the plugin applies sanitize_text_field() to firstName and lastName parameters, this function does not remove double quotes. 

The vulnerability is triggered when the application renders the customer name in the administrative Calendar view. The plugin utilizes a FullCalendar eventContent callback that interpolates these names directly into JavaScript template literals and renders them via innerHTML without HTML entity encoding. By breaking out of the JavaScript context using a double quote, an attacker can inject arbitrary JavaScript event handlers. This results in the execution of malicious scripts within the browser session of an administrator who views the compromised event in the WordPress dashboard.

## Attack Chain

1. Attacker identifies a WordPress site with the Amelia plugin (v2.2 or lower).
2. Attacker probes the appointment booking API to locate the AddBookingCommand endpoint.
3. Attacker crafts a malicious booking request containing an XSS payload (e.g., '" onmouseover="alert(document.cookie)"') in the customer firstName field.
4. Attacker sends the POST request to the endpoint, bypassing nonce verification due to the flaw in Command.php.
5. The plugin saves the malicious string to the database via BookingApplicationService.php.
6. A privileged administrator navigates to the Amelia Calendar page in the WordPress dashboard.
7. The Calendar page retrieves the malicious booking data and renders it unsafely via innerHTML in the browser.
8. The administrator's browser executes the injected JavaScript upon interacting with the event.

## Impact

Successful exploitation results in arbitrary JavaScript execution within an administrative session. This enables attackers to perform unauthorized actions on behalf of the administrator, such as creating new rogue accounts, modifying plugin settings, or stealing administrative session cookies to facilitate account takeover. The impact is significant for organizations relying on the Amelia plugin to manage external-facing appointment workflows.

## Recommendation

1. Immediately update the Amelia plugin to a version patched against CVE-2026-6286.
2. Implement a Web Application Firewall (WAF) rule to inspect POST requests directed to the WordPress admin API, specifically monitoring for unusual characters like double quotes or JavaScript event handlers in booking parameters.
3. Restrict access to the WordPress administrative dashboard to known-trusted IP addresses to reduce the likelihood of an administrator interacting with malicious payloads.
4. Monitor WordPress access logs for high volumes of POST requests to booking endpoints from single IP addresses, which may indicate automated booking abuse.
