---
title: Vulnerability in Ruby on Rails Allows Remote Indirect Code Injection (XSS)
slug: 2026-07-ruby-on-rails-xss
description: A cross-site scripting (XSS) vulnerability has been discovered in Ruby on Rails versions prior to 1.7.1, enabling a remote attacker to perform an indirect remote code injection, allowing malicious scripts to be executed in the client's browser.
date: "2026-07-16T12:55:54Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - xss
  - web-vulnerability
  - ruby-on-rails
  - cross-site-scripting
vendors:
  - Ruby on Rails
products:
  - Ruby on Rails < 1.7.1
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Elle permet à un attaquant de provoquer une injection de code indirecte à distance (XSS).
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0891/
  - https://discuss.rubyonrails.org/t/ghsa-cj75-f6xr-r4g7-possible-xss-vulnerability-with-certain-configurations-of-rails-html-sanitizer/91359
iocs:
  - type: url
    value: https://discuss.rubyonrails.org/t/ghsa-cj75-f6xr-r4g7-possible-xss-vulnerability-with-certain-configurations-of-rails-html-sanitizer/91359
ioc_counts:
  url: 1
---

A vulnerability has been identified in Ruby on Rails versions older than 1.7.1, as detailed by CERT-FR. This flaw, categorized as an indirect remote code injection (Cross-Site Scripting or XSS), allows an attacker to inject malicious scripts into web pages viewed by other users. When a victim's browser renders a page containing the injected script, the script executes within the user's browser context. While the source does not specify active exploitation, the nature of XSS vulnerabilities can lead to severe client-side attacks, including session hijacking, data theft, or defacement. Defenders must prioritize updating affected Ruby on Rails applications to version 1.7.1 or newer to mitigate this risk.

## Attack Chain

1. **Vulnerability Identification**: An attacker identifies a web application utilizing a vulnerable version of Ruby on Rails (prior to 1.7.1) that is susceptible to XSS.
2. **Payload Crafting**: The attacker designs a malicious JavaScript payload intended to achieve objectives such as stealing session cookies, redirecting users to phishing sites, or defacing web content.
3. **Payload Injection**: The attacker injects the crafted payload into an input field, URL parameter, or other data input mechanism within the vulnerable Ruby on Rails application. This data is then stored or reflected by the application without proper sanitization.
4. **Victim Interaction**: A legitimate user accesses a web page or resource within the Ruby on Rails application that contains or reflects the previously injected malicious payload.
5. **Client-Side Execution**: The vulnerable Ruby on Rails application renders the web page, inadvertently including the attacker's script as part of the legitimate HTML content. The victim's web browser then executes this embedded JavaScript.
6. **Impact on Victim**: The malicious script executes within the security context of the victim's browser, potentially leading to unauthorized access to user data, theft of session cookies for account hijacking, or other client-side compromises.

## Impact

Successful exploitation of this XSS vulnerability could allow attackers to execute arbitrary client-side scripts in the context of a victim's browser. This can lead to severe consequences such as session hijacking, allowing attackers to impersonate legitimate users and gain unauthorized access to their accounts. Other potential impacts include sensitive data exfiltration from the victim's browser, defacement of web pages, or redirection to malicious websites. Although no specific victim numbers or targeted sectors were mentioned, any organization using affected Ruby on Rails versions could be at risk.

## Recommendation

* Refer to the Ruby on Rails security bulletin referenced in this brief and immediately apply the patch by updating to Ruby on Rails version 1.7.1 or newer.
* Implement robust input validation and output encoding across all Ruby on Rails applications to prevent future XSS vulnerabilities, ensuring user-supplied data is properly sanitized before being rendered to web pages.
