---
title: Kaspersky Anti Targeted Attack Platform Multiple XSS Vulnerabilities
slug: 2026-05-kaspersky-ata-xss
description: Multiple vulnerabilities have been discovered in Kaspersky Anti Targeted Attack Platform versions prior to 7.1.7, allowing an attacker to cause a remote cross-site scripting (XSS) vulnerability, tracked as CVE-2026-28348 and CVE-2026-28350.
date: "2026-05-27T14:31:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:fedoralovespython:lxml_html_clean:*:*:*:*:*:python:*:*
tags:
  - xss
  - vulnerability
  - web-application
vendors:
  - Kaspersky
products:
  - Anti Targeted Attack Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-28348
    cvss: 6.1
    epss: 0.00051
  - id: CVE-2026-28350
    cvss: 6.1
    epss: 0.00016
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0648/
  - https://support.kaspersky.com/vulnerability/list-of-advisories/12430#260526
  - https://www.cve.org/CVERecord?id=CVE-2026-28348
  - https://www.cve.org/CVERecord?id=CVE-2026-28350
rules:
  - title: Detects CVE-2026-28348 and CVE-2026-28350 Exploitation — Suspicious URI Containing Scripting Keywords
    description: Detects CVE-2026-28348 and CVE-2026-28350 exploitation — Suspicious URI access containing common scripting keywords indicative of XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-28348 and CVE-2026-28350 Exploitation — Suspicious POST Data Containing Scripting Keywords
    description: Detects CVE-2026-28348 and CVE-2026-28350 exploitation — Suspicious POST data containing common scripting keywords indicative of XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been discovered in Kaspersky Anti Targeted Attack Platform. These vulnerabilities, tracked as CVE-2026-28348 and CVE-2026-28350, can be exploited to perform a remote cross-site scripting (XSS) attack. This impacts versions of Kaspersky Anti Targeted Attack Platform prior to 7.1.7. Exploitation of these vulnerabilities allows an attacker to inject malicious scripts into the web pages viewed by other users. A successful XSS attack can lead to session hijacking, defacement of websites, or redirection of users to malicious sites.

## Attack Chain

1. The attacker identifies a vulnerable endpoint within the Kaspersky Anti Targeted Attack Platform web application. This endpoint accepts user-controlled input without proper sanitization.
2. The attacker crafts a malicious URL or injects malicious code into a form field that will be processed by the vulnerable endpoint. This malicious code includes JavaScript or other client-side scripting languages.
3. The attacker delivers the crafted URL to a victim user, typically through phishing, social engineering, or by injecting the link into another part of the application.
4. The victim user clicks on the malicious link or interacts with the injected form.
5. The vulnerable endpoint processes the attacker-supplied input and embeds it into the HTML response without proper encoding or sanitization.
6. The victim's web browser renders the HTML response, executing the attacker's injected script.
7. The injected script executes within the security context of the victim's browser, allowing the attacker to access cookies, session tokens, and other sensitive information.
8. The attacker uses the stolen information to hijack the victim's session, deface the web application, or redirect the victim to a malicious website.

## Impact

Successful exploitation of these XSS vulnerabilities (CVE-2026-28348, CVE-2026-28350) in Kaspersky Anti Targeted Attack Platform can lead to unauthorized access to sensitive data, including user credentials and internal system information. The impact ranges from defacement to complete account takeover. Since the vulnerability exists in a security product, successful exploitation severely undermines the security posture of affected organizations. The number of potential victims depends on the user base of the affected Kaspersky Anti Targeted Attack Platform installations.

## Recommendation

*   Upgrade Kaspersky Anti Targeted Attack Platform to version 7.1.7 or later to remediate CVE-2026-28348 and CVE-2026-28350 (see Kaspersky Security Bulletin 12430#260526).
*   Implement a Web Application Firewall (WAF) with rules to detect and block common XSS attack patterns targeting the Kaspersky Anti Targeted Attack Platform web interface.
*   If upgrading is not immediately feasible, consider implementing input validation and output encoding on the Kaspersky Anti Targeted Attack Platform web interface as a temporary mitigation.
