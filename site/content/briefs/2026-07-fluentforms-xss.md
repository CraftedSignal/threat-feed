---
title: Fluent Forms WordPress Plugin Stored Cross-Site Scripting Vulnerability (CVE-2026-16655)
slug: 2026-07-fluentforms-xss
description: An unauthenticated attacker can exploit a Stored Cross-Site Scripting vulnerability (CVE-2026-16655) in the Fluent Forms WordPress plugin, versions up to and including 6.2.7, via insufficient input sanitization of the Name Field Nested `password` Member, allowing injection of arbitrary web scripts that execute in a user's browser upon page access.
date: "2026-07-29T11:21:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - xss
  - vulnerability
  - webserver
vendors:
  - wpmanageninja
products:
  - Fluent Forms – Customizable Contact Forms, Survey, Quiz, & Conversational Form Builder (<= 6.2.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: ""
    evidence: This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-16655
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16655
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.6/app/Hooks/Ajax.php#L17
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.6/app/Modules/Form/FormDataParser.php#L317
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.6/app/Modules/SubmissionHandler/SubmissionHandler.php#L20
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.6/app/Services/Form/SubmissionHandlerService.php#L123
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.6/app/Services/Integrations/GlobalNotificationService.php#L59
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.6/boot/globals.php#L110
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.7/app/Hooks/Ajax.php#L17
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.7/app/Modules/Form/FormDataParser.php#L317
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.7/app/Modules/SubmissionHandler/SubmissionHandler.php#L20
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.7/app/Services/Form/SubmissionHandlerService.php#L123
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.7/app/Services/Integrations/GlobalNotificationService.php#L59
  - https://plugins.trac.wordpress.org/browser/fluentform/tags/6.2.7/boot/globals.php#L110
  - https://plugins.trac.wordpress.org/changeset/3619584/fluentform/trunk/boot/globals.php
  - https://plugins.trac.wordpress.org/changeset?old_path=%2Ffluentform/tags/6.2.7&new_path=%2Ffluentform/tags/6.2.8
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/635e19ba-da98-459c-ab91-ff969b0812fd?source=cve
---

A critical Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-16655, has been identified in the Fluent Forms - Customizable Contact Forms, Survey, Quiz, & Conversational Form Builder plugin for WordPress. This flaw impacts all plugin versions up to and including 6.2.7. The vulnerability stems from insufficient input sanitization and output escaping of data within the "Name Field Nested `password` Member." An unauthenticated attacker can leverage this weakness to inject malicious web scripts into web pages. When a legitimate user, such as an administrator, subsequently accesses these injected pages, the malicious scripts will execute within their browser context, potentially leading to session hijacking, sensitive data theft, or arbitrary actions on behalf of the victim. This vulnerability poses a significant risk to the integrity and security of WordPress sites utilizing the affected plugin.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site running the vulnerable Fluent Forms plugin, version 6.2.7 or earlier.
2. The attacker crafts a malicious payload containing JavaScript code.
3. The attacker submits this crafted payload into the "Name Field Nested `password` Member" input of a Fluent Forms form on the target website.
4. Due to insufficient input sanitization and output escaping, the plugin stores the malicious script without properly neutralizing it.
5. The malicious script becomes embedded within the website's database and rendered on web pages where the "Name Field Nested `password` Member" content is displayed.
6. A legitimate user, such as a site administrator, accesses a page containing the maliciously injected content.
7. The embedded script executes within the user's browser, allowing the attacker to perform actions like stealing session cookies, defacing the website, redirecting the user to malicious sites, or exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-16655 can lead to a severe compromise of the affected WordPress site and its users. An attacker can hijack user sessions, including those of administrators, gaining full control over the compromised accounts. This could result in unauthorized modification of website content, redirection of visitors to malicious sites, or the deployment of further client-side attacks. The vulnerability affects a widely used WordPress plugin, potentially exposing a broad range of websites to these risks. The CVSS v3.1 Base Score of 7.2 (High) reflects the significant security implications, particularly the potential for complete control over user sessions and client-side data.

## Recommendation

* Immediately update the Fluent Forms - Customizable Contact Forms, Survey, Quiz, & Conversational Form Builder plugin to a version beyond 6.2.7 to patch CVE-2026-16655.
* Implement a Web Application Firewall (WAF) to detect and block common XSS attack patterns in HTTP request bodies and parameters, providing a layer of defense against vulnerabilities like CVE-2026-16655.
* Ensure server-side input validation and output encoding are rigorously applied for all user-supplied data in web applications to prevent similar Stored XSS vulnerabilities.
