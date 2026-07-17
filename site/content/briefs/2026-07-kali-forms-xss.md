---
title: Kali Forms WordPress Plugin Vulnerable to Stored Cross-Site Scripting via digitalSignature Field
slug: 2026-07-kali-forms-xss
description: The Kali Forms - Contact Form & Drag-and-Drop Builder plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'digitalSignature' field in versions up to and including 2.4.18, allowing unauthenticated attackers to inject arbitrary web scripts that execute when a user accesses an affected page.
date: "2026-07-17T04:18:39Z"
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
  - stored-xss
vendors:
  - Kali Forms
  - WordPress
products:
  - Kali Forms - Contact Form & Drag-and-Drop Builder (<= 2.4.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can inject arbitrary web scripts... making this exploitable by fully unauthenticated attackers.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: med
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: high
cves:
  - id: CVE-2026-15395
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15395
rules:
  - title: Detect Possible Kali Forms XSS Exploitation Attempts
    description: Detects CVE-2026-15395 exploitation - potential Stored XSS injection attempts targeting the 'digitalSignature' field of Kali Forms in WordPress via common XSS payload patterns in webserver logs.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1588
    data_sources:
      - webserver
rules_count: 1
---

The Kali Forms - Contact Form & Drag-and-Drop Builder plugin for WordPress, a widely used tool for creating customizable contact forms, is susceptible to a critical Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-15395. This flaw affects all plugin versions up to and including 2.4.18. The vulnerability stems from insufficient input sanitization and output escaping, specifically impacting the 'digitalSignature' field. This design oversight enables unauthenticated attackers to embed arbitrary web scripts into form submissions. Crucially, the form-submission nonce, a security token typically required for form validity, is publicly available on any page hosting a Kali Forms shortcode. This accessibility streamlines exploitation for attackers, allowing them to bypass authentication requirements and inject malicious scripts that execute whenever a legitimate user, such as a site administrator, views the compromised pages or submitted form entries. The broad usage of the plugin makes this a significant concern for WordPress site owners.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress website utilizing the Kali Forms plugin.
2. The attacker browses the website to locate a publicly accessible page that displays a Kali Forms shortcode.
3. The attacker extracts the necessary form-submission nonce, which is publicly available in the page's source code or network traffic, without requiring authentication.
4. The attacker crafts a malicious HTTP POST request targeting the Kali Forms submission endpoint, embedding the extracted nonce.
5. Within this crafted POST request, the attacker injects arbitrary web scripts (e.g., `<script>alert('XSS')</script>`) into the vulnerable 'digitalSignature' field.
6. The malicious form data, including the embedded script, is submitted and stored by the Kali Forms plugin.
7. A legitimate user, such as a website administrator, later accesses the backend or a frontend page where this stored form submission data is rendered.
8. The injected web script executes within the victim's browser, potentially leading to session hijacking, defacement of the website, credential theft, or redirection to malicious sites.

## Impact

Successful exploitation of CVE-2026-15395 can lead to significant compromise of the affected WordPress website and its users. Attackers can execute arbitrary JavaScript in the context of the victim's browser, which can include session hijacking, allowing them to take over administrator accounts, defacing website content, redirecting users to malicious sites, or stealing sensitive user data like login credentials or personal information. Due to the unauthenticated nature of the vulnerability and the public availability of the nonce, a wide range of WordPress sites using the Kali Forms plugin are at risk if not updated. The CVSS v3.1 Base Score of 7.2 reflects the high severity and potential for widespread damage.

## Recommendation

* Update the Kali Forms - Contact Form & Drag-and-Drop Builder plugin to version 2.4.19 or higher immediately to patch CVE-2026-15395.
* Deploy the Sigma rule "Detect Possible Kali Forms XSS Exploitation Attempts" to your SIEM to identify attempts at injecting malicious scripts through web requests.
* Review webserver access logs and internal application logs for patterns indicating XSS injection attempts in form submission data, especially for parameters related to the `digitalSignature` field.
