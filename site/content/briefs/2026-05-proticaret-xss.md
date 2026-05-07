---
title: Proticaret E-Commerce Reflected XSS Vulnerability (CVE-2026-3953)
slug: 2026-05-proticaret-xss
description: A reflected cross-site scripting (XSS) vulnerability exists in Gosoft Software Industry and Trade Ltd. Co.'s Proticaret E-Commerce software (versions v5.0.0 before V 6.0.1767.1383) due to improper neutralization of input during web page generation, potentially allowing attackers to execute arbitrary JavaScript in a user's browser.
date: "2026-05-07T12:16:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - cross-site scripting
  - reflected xss
  - web application vulnerability
vendors:
  - Gosoft Software Industry and Trade Ltd. Co.
products:
  - Proticaret E-Commerce (>= 5.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-3953
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3953
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0180
rules:
  - title: Detect Proticaret E-Commerce XSS Attempt via URL
    description: Detects potential reflected XSS attempts targeting Proticaret E-Commerce by identifying common JavaScript injection patterns in the URL.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Proticaret E-Commerce XSS Attempt in POST Request
    description: Detects potential reflected XSS attempts targeting Proticaret E-Commerce in POST requests by identifying common JavaScript injection patterns in the request body.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A reflected XSS vulnerability, identified as CVE-2026-3953, has been discovered in Proticaret E-Commerce, a product by Gosoft Software Industry and Trade Ltd. Co. The vulnerability stems from the improper neutralization of user-supplied input during web page generation. This allows an attacker to inject malicious JavaScript code into a web page, which is then executed by the victim's browser when they visit the crafted URL. The affected versions range from v5.0.0 to before V 6.0.1767.1383. This vulnerability can be exploited if a user clicks on a specially crafted link, potentially leading to session hijacking, defacement, or redirection to malicious websites.

## Attack Chain

1.  Attacker crafts a malicious URL containing JavaScript code in a parameter.
2.  The attacker distributes the crafted URL via email, social media, or other means to a target user.
3.  The user clicks on the malicious URL, sending a request to the vulnerable Proticaret E-Commerce web server.
4.  The Proticaret E-Commerce application fails to properly sanitize the input from the URL.
5.  The application reflects the unsanitized input back to the user's browser in the HTTP response.
6.  The user's browser executes the injected JavaScript code within the context of the Proticaret E-Commerce website.
7.  The attacker can then perform actions such as stealing cookies, redirecting the user, or defacing the web page.

## Impact

Successful exploitation of this reflected XSS vulnerability (CVE-2026-3953) could allow an attacker to execute arbitrary JavaScript code in the context of the user's browser. This can lead to session hijacking, where the attacker gains unauthorized access to the user's account. Additionally, the attacker could deface the website, redirect the user to a malicious site, or gather sensitive information. The scope of the impact depends on the privileges of the affected user within the Proticaret E-Commerce application.

## Recommendation

*   Upgrade Proticaret E-Commerce to version 6.0.1767.1383 or later to patch CVE-2026-3953.
*   Deploy the Sigma rule "Detect Proticaret E-Commerce XSS Attempt via URL" to identify and block malicious requests.
*   Implement robust input validation and output encoding techniques to prevent XSS vulnerabilities in Proticaret E-Commerce and other web applications.
