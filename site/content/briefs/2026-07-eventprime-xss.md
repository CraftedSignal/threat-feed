---
title: EventPrime WordPress Plugin Stored XSS (CVE-2026-13441)
slug: 2026-07-eventprime-xss
description: A critical stored Cross-Site Scripting (XSS) vulnerability, CVE-2026-13441, exists in all versions up to 4.3.4.2 of the EventPrime - Events Calendar, Bookings and Tickets plugin for WordPress, allowing authenticated attackers with custom-level access (or unauthenticated attackers if 'Guest Submissions' is enabled) to inject malicious web scripts via the new_event_type_background_color parameter that execute whenever a user accesses an affected page, potentially leading to session hijacking, defacement, or further compromise.
date: "2026-07-09T11:18:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - wordpress
  - xss
  - plugin
vendors:
  - EventPrime
  - WordPress
products:
  - EventPrime – Events Calendar, Bookings and Tickets plugin (<= 4.3.4.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The EventPrime – Events Calendar, Bookings and Tickets plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'new_event_type_background_color' parameter.
    confidence_band: high
cves:
  - id: CVE-2026-13441
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13441
rules:
  - title: Detects CVE-2026-13441 Exploitation Attempt - EventPrime Stored XSS
    description: Detects exploitation attempts for CVE-2026-13441, a Stored Cross-Site Scripting vulnerability in the EventPrime WordPress plugin, by identifying common XSS payloads within the 'new_event_type_background_color' parameter in web requests.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A significant stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-13441, has been identified in the EventPrime - Events Calendar, Bookings and Tickets plugin for WordPress. This flaw impacts all versions up to and including 4.3.4.2. The vulnerability stems from insufficient input sanitization and output escaping when handling the `new_event_type_background_color` parameter. Attackers can exploit this by injecting arbitrary web scripts into pages that subsequently execute when viewed by other users. Exploitation typically requires an authenticated user with custom-level access or higher. However, if the plugin's `Guest Submissions` setting (`allow_submission_by_anonymous_user`) is enabled, even unauthenticated individuals can leverage frontend forms to inject malicious scripts. Successful exploitation can lead to session hijacking, data theft, website defacement, or redirection to malicious sites, posing a direct threat to the integrity and security of affected WordPress installations and their users. Defenders should prioritize patching and monitoring for suspicious web requests targeting this plugin.

## Attack Chain

1. **Reconnaissance & Vulnerability Identification**: An attacker identifies a WordPress website running the EventPrime plugin (versions <= 4.3.4.2) and confirms the presence of the vulnerability, potentially by checking plugin version numbers.
2. **Initial Access / Authentication**: The attacker either obtains credentials for a custom-level (or higher) WordPress user account or identifies that the EventPrime plugin's "Guest Submissions" setting is enabled, allowing unauthenticated submissions.
3. **Malicious Payload Crafting**: The attacker develops a Stored XSS payload (e.g., `<script>alert(document.domain);</script>`, `<img src=x onerror=alert(1)>`) specifically designed to execute in a victim's browser context.
4. **Injection via Parameter**: The attacker sends an HTTP POST request to the EventPrime plugin's event creation or submission endpoint, embedding the malicious XSS payload within the `new_event_type_background_color` parameter.
5. **Payload Persistence**: Due to the plugin's insufficient input sanitization, the WordPress backend stores the malicious `new_event_type_background_color` value, including the XSS payload, in its database.
6. **Victim Interaction & Trigger**: A legitimate user, such as a site administrator or another visitor, navigates to a WordPress page where the crafted event type (containing the vulnerable parameter) is displayed.
7. **Client-Side Execution**: The victim's web browser renders the page, retrieves the stored malicious `new_event_type_background_color` value, and executes the injected JavaScript code in the context of the victim's session.
8. **Impact & Objective**: The executed script performs its intended action, such as stealing the victim's session cookies (leading to session hijacking), defacing the web page, redirecting the user to a phishing site, or initiating further client-side attacks.

## Impact

Successful exploitation of CVE-2026-13441 can have severe consequences for affected WordPress websites and their users. Attackers can hijack administrator sessions, leading to full site compromise, data exfiltration, or the injection of additional malware. For regular users, XSS can facilitate phishing attacks, credential theft, or drive-by downloads. The integrity and reputation of the targeted organization can be significantly damaged due to defaced content or widespread malicious redirects. While specific victim counts are not available, the widespread use of WordPress and popular plugins like EventPrime means a large number of organizations across various sectors could be vulnerable, particularly those not maintaining timely updates or enabling guest submission features.

## Recommendation

* Patch CVE-2026-13441 immediately by updating the EventPrime - Events Calendar, Bookings and Tickets plugin to a version greater than 4.3.4.2.
* Enable comprehensive web server logging to capture full HTTP request details, including query strings and potentially POST bodies, to allow detection of XSS injection attempts.
* Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect attempts to exploit CVE-2026-13441.
* Review EventPrime's `Guest Submissions` setting (`allow_submission_by_anonymous_user`) and disable it if not strictly required, to mitigate the risk of unauthenticated exploitation of CVE-2026-13441.
