---
title: cPanel cPanel/WHM Vulnerability Allows Header Manipulation
slug: 2026-05-cpanel-header-injection
description: A remote, anonymous attacker can exploit a vulnerability in cPanel cPanel/WHM to perform an HTTP response header injection, enabling cross-site scripting (XSS), open redirect attacks, and cache or header manipulation.
date: "2026-05-22T07:26:29Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - cpanel
  - header-injection
  - xss
  - open-redirect
vendors:
  - cPanel
products:
  - cPanel/WHM
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2012
rules:
  - title: Detect cPanel HTTP Header Injection Attempt
    description: Detects potential HTTP Header Injection attacks against cPanel/WHM by identifying suspicious characters in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect cPanel Open Redirect via Header Injection
    description: Detects Open Redirect attempts against cPanel/WHM by looking for 'Location:' in URI query strings, indicating header injection
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists within cPanel cPanel/WHM that allows a remote, unauthenticated attacker to inject arbitrary HTTP response headers. This weakness stems from insufficient sanitization of input used in crafting the HTTP response, leading to potential security compromises. Successful exploitation can lead to a range of attacks, including Cross-Site Scripting (XSS) and open redirects. These attacks can be leveraged to steal user credentials, redirect users to malicious websites, or deface legitimate websites. The manipulation of HTTP headers could also be used to poison caches, serving malicious content to unsuspecting users. This vulnerability poses a risk to all cPanel/WHM installations that have not applied the necessary security patches.

## Attack Chain

1. The attacker identifies a cPanel/WHM endpoint vulnerable to HTTP header injection.
2. The attacker crafts a malicious HTTP request containing specially crafted input designed to inject arbitrary headers.
3. The cPanel/WHM server processes the malicious request without proper sanitization.
4. The injected headers are incorporated into the HTTP response sent back to the user's browser.
5. If the injected header contains JavaScript code, it is executed in the user's browser, leading to XSS.
6. If the injected header contains a redirect directive, the user is redirected to a malicious website, resulting in an Open Redirect attack.
7. The attacker leverages XSS or Open Redirect to steal user credentials or deliver malware.
8. Alternatively, the injected headers could manipulate caching mechanisms, leading to cache poisoning and the delivery of malicious content to multiple users.

## Impact

Successful exploitation of this vulnerability can have significant consequences. Attackers can gain unauthorized access to user accounts through XSS attacks, leading to data breaches and identity theft. Open redirect attacks can be used to phish users or distribute malware. Furthermore, cache poisoning can lead to widespread distribution of malicious content, affecting a large number of users and damaging the reputation of the affected website.

## Recommendation

*   Apply the latest security patches provided by cPanel to mitigate the HTTP header injection vulnerability (reference: cPanel/WHM product).
*   Implement robust input validation and sanitization techniques to prevent the injection of malicious characters into HTTP headers (reference: cPanel/WHM product).
*   Deploy the Sigma rule "Detect cPanel HTTP Header Injection Attempt" to identify and alert on suspicious HTTP requests targeting cPanel/WHM (reference: Sigma rule).
*   Monitor web server logs for unusual HTTP response headers or redirect attempts (reference: webserver log source).
