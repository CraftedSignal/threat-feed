---
title: PrestaShop Stored XSS in Customer Service View Allows Back-Office Takeover
slug: 2026-05-prestashop-xss
description: A stored cross-site scripting (XSS) vulnerability exists in PrestaShop's back-office customer service view, where an unauthenticated attacker can submit a malicious email address via the Contact Us form, leading to session hijacking and full back-office takeover when an employee opens the affected customer thread; patched in PrestaShop 8.2.6 and 9.1.1.
date: "2026-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prestashop
  - xss
  - stored-xss
  - cve-2026-44212
vendors:
  - PrestaShop
products:
  - PrestaShop (< 8.2.6)
  - PrestaShop (>= 9.0.0, < 9.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-w9f3-qc75-qgx9
iocs:
  - type: email
    value: anthropic@doyensec.com
ioc_counts:
  email: 1
rules:
  - title: Detect PrestaShop Stored XSS via Contact Form
    description: Detects CVE-2026-44212 exploitation — attempts to inject XSS payloads via the PrestaShop contact form by looking for unusual characters in the email address.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect PrestaShop Backoffice Access after Potential XSS
    description: Detects suspicious access to PrestaShop backoffice after potential XSS injection attempts via contact form. This detection needs to be correlated with the first rule for higher fidelity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
rules_count: 2
---

A critical stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-44212, affects the Customer Service view of PrestaShop versions prior to 8.2.6 and between 9.0.0 and 9.1.1. This flaw allows an unauthenticated attacker to inject malicious JavaScript code into the system by submitting a crafted email address through the public Contact Us form. The injected payload is then stored within the PrestaShop database. When a back-office employee accesses the affected customer thread through the back-office interface, the stored XSS payload is executed, potentially leading to session hijacking and complete compromise of the PrestaShop back-office environment. This vulnerability was reported by Savio at Doyensec in collaboration with Anthropic Research.

## Attack Chain

1.  The attacker crafts a malicious email address containing an XSS payload.
2.  The attacker submits the crafted email address through the public Contact Us form on the PrestaShop website.
3.  The PrestaShop application stores the attacker-supplied email address and the associated XSS payload in the database, specifically within the customer service messaging system.
4.  A back-office employee accesses the customer service section of the PrestaShop administration panel.
5.  The employee opens the customer thread associated with the malicious email address.
6.  The PrestaShop application retrieves the stored email address from the database and renders it in the back-office interface.
7.  The stored XSS payload within the email address is executed by the employee's web browser, due to the lack of proper sanitization and output encoding.
8.  The attacker gains control of the employee's session, potentially allowing them to perform administrative actions, access sensitive data, or further compromise the PrestaShop installation.

## Impact

Successful exploitation of this stored XSS vulnerability allows an attacker to hijack the session of a PrestaShop back-office employee. This can lead to full control over the PrestaShop installation, including access to sensitive customer data, modification of store settings, installation of malicious modules, and ultimately, complete compromise of the e-commerce platform. Given the critical nature of the back-office, this poses a significant risk to the confidentiality, integrity, and availability of the PrestaShop store. Patches have been released in PrestaShop versions 8.2.6 and 9.1.1 to address this issue.

## Recommendation

*   Upgrade PrestaShop installations to version 8.2.6 or 9.1.1 or later to remediate CVE-2026-44212.
*   Deploy the Sigma rule "Detect PrestaShop Stored XSS via Contact Form" to identify attempts to inject malicious code via the contact form.
*   Investigate any alerts triggered by the "Detect PrestaShop Stored XSS via Contact Form" Sigma rule, focusing on unusual characters in email addresses submitted via the contact form.
*   Implement robust input validation and output encoding mechanisms within the PrestaShop application to prevent XSS vulnerabilities.
