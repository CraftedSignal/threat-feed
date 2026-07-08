---
title: 'CVE-2026-6820: VikBooking WordPress Plugin Stored XSS Vulnerability'
slug: 2026-07-vikbooking-xss
description: An unauthenticated Stored Cross-Site Scripting vulnerability (CVE-2026-6820) in the VikBooking Hotel Booking Engine & PMS plugin for WordPress versions up to 1.8.8 allows attackers to inject malicious web scripts via the 'email' parameter, leading to client-side code execution in victims' browsers.
date: "2026-07-08T13:21:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - xss
  - web-vulnerability
vendors:
  - e4j
  - WordPress Foundation
products:
  - VikBooking Hotel Booking Engine & PMS (<= 1.8.8)
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-6820
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6820
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/e2b4586a-f87d-4a51-8f4e-932d7254518e?source=cve
  - https://plugins.trac.wordpress.org/browser/vikbooking/tags/1.8.9/admin/controller.php#L11208
  - https://plugins.trac.wordpress.org/browser/vikbooking/tags/1.8.9/site/controller.php#L307
---

A critical vulnerability, identified as CVE-2026-6820, has been discovered in the VikBooking Hotel Booking Engine & PMS plugin for WordPress, affecting all versions up to and including 1.8.8. This Stored Cross-Site Scripting (XSS) flaw stems from insufficient input sanitization and output escaping of the 'email' parameter. Unauthenticated attackers can exploit this by injecting malicious web scripts into the plugin's data. These scripts are then persistently stored and subsequently executed in the browsers of legitimate users or administrators who access an affected page. The vulnerability, publicly disclosed on July 8, 2026, poses a significant risk to websites using the plugin, potentially leading to session hijacking, defacement, or further client-side exploitation without requiring any prior authentication from the attacker.

## Attack Chain

1. An unauthenticated attacker crafts an HTTP POST request targeting a WordPress endpoint handled by the VikBooking plugin (e.g., a booking form submission or a profile update function accessible to unauthenticated users).
2. The attacker embeds a malicious JavaScript payload within the 'email' parameter of this POST request, for instance, `<script>alert('XSS');</script>`.
3. Due to inadequate input validation, the VikBooking plugin processes and stores this unsanitized 'email' parameter, including the embedded script, into the WordPress database.
4. The malicious script becomes persistently stored on the server as part of the plugin's data, associated with a booking or user entry.
5. A legitimate user or administrator subsequently navigates to a WordPress page (e.g., a booking details page, an admin panel view) that retrieves and displays the compromised 'email' parameter from the database.
6. When the affected page loads in the victim's browser, the stored malicious JavaScript payload is executed within the context of the victim's session.
7. This client-side execution can lead to session hijacking (e.g., cookie theft), redirection to malicious sites, defacement of the webpage, or the download and execution of further malware.
8. The attacker achieves their objective, potentially gaining unauthorized access to sensitive information or control over the victim's session.

## Impact

The successful exploitation of CVE-2026-6820 can lead to severe consequences for organizations utilizing the VikBooking Hotel Booking Engine & PMS plugin. Attackers can hijack administrator sessions, leading to full compromise of the WordPress site, including data exfiltration, website defacement, or malware distribution to visitors. For regular users, session hijacking could expose personal booking details or lead to credential theft via phishing. Given the plugin's function, hospitality businesses and any entity managing bookings online are particularly vulnerable. While no specific victim count is available, the widespread use of WordPress and its plugins suggests a significant potential attack surface, impacting reputation, data privacy, and operational continuity.

## Recommendation

1. Immediately update the VikBooking Hotel Booking Engine & PMS plugin to version 1.8.9 or higher to patch CVE-2026-6820.
2. Deploy or update Web Application Firewall (WAF) rules to detect and block common Stored XSS payloads, specifically targeting inputs to WordPress endpoints that handle the 'email' parameter as described for CVE-2026-6820.
3. Review web server access logs (e.g., Apache, Nginx) for HTTP POST requests to WordPress paths containing the 'email' parameter with suspicious characters, such as `<script>`, `onerror=`, or `javascript:`, which could indicate exploitation attempts of CVE-2026-6820.
4. Conduct security audits of all WordPress installations and plugins to identify and remediate similar input sanitization and output escaping vulnerabilities.
