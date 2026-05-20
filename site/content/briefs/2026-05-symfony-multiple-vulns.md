---
title: Multiple Vulnerabilities in Symfony Framework
slug: 2026-05-symfony-multiple-vulns
description: Multiple vulnerabilities in Symfony, including CVE-2026-45070, CVE-2026-45077, CVE-2026-45304, CVE-2026-45305, CVE-2026-45753, CVE-2026-45754, CVE-2026-45755, CVE-2026-45756, CVE-2026-46626, and CVE-2026-47212, can lead to remote denial of service, cross-site scripting (XSS), and cross-site request forgery (CSRF) attacks.
date: "2026-05-20T14:08:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - symfony
  - vulnerability
  - dos
  - xss
  - csrf
vendors:
  - Symfony
products:
  - symfony/html-sanitizer
  - symfony/json-path
  - symfony/lox24-notifier
  - symfony/mailjet-mailer
  - symfony/mailtrap-mailer
  - symfony/mime
  - symfony/monolog-bridge
  - symfony/runtime
  - symfony/symfony
  - symfony/twilio-notifier
  - symfony/yaml
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0617/
  - https://github.com/symfony/symfony/security/advisories/GHSA-4qpc-3hr4-r2p4
  - https://github.com/symfony/symfony/security/advisories/GHSA-55rj-x2vc-4whq
  - https://github.com/symfony/symfony/security/advisories/GHSA-59f3-vp2f-mp9w
  - https://github.com/symfony/symfony/security/advisories/GHSA-64hg-93w9-fc35
  - https://github.com/symfony/symfony/security/advisories/GHSA-8v8v-g73j-492j
  - https://github.com/symfony/symfony/security/advisories/GHSA-9frc-8383-795m
  - https://github.com/symfony/symfony/security/advisories/GHSA-fqc7-9xjw-jrh3
  - https://github.com/symfony/symfony/security/advisories/GHSA-hhg7-c65m-h7ff
  - https://github.com/symfony/symfony/security/advisories/GHSA-m7v2-7gxm-vc2v
  - https://github.com/symfony/symfony/security/advisories/GHSA-vqc8-7275-q272
  - https://www.cve.org/CVERecord?id=CVE-2026-45070
  - https://www.cve.org/CVERecord?id=CVE-2026-45077
  - https://www.cve.org/CVERecord?id=CVE-2026-45304
  - https://www.cve.org/CVERecord?id=CVE-2026-45305
  - https://www.cve.org/CVERecord?id=CVE-2026-45753
  - https://www.cve.org/CVERecord?id=CVE-2026-45754
  - https://www.cve.org/CVERecord?id=CVE-2026-45755
  - https://www.cve.org/CVERecord?id=CVE-2026-45756
  - https://www.cve.org/CVERecord?id=CVE-2026-46626
  - https://www.cve.org/CVERecord?id=CVE-2026-47212
rules:
  - title: Detect CVE-2026-45070 and others - Suspicious HTTP Request Headers (XSS)
    description: Detects potential XSS attempts in HTTP request headers targeting Symfony applications by looking for common script tags or event handlers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-45077 and others - Potential CSRF Attempt via Modified Referer
    description: Detects potential CSRF attempts in Symfony applications by looking for requests with missing or suspicious Referer headers.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect CVE-2026-45304 and others - Excessive Request Rate (Potential DoS)
    description: Detects potential denial-of-service attempts targeting Symfony applications by monitoring for excessive request rates from a single IP address.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 3
---

On May 20, 2026, CERT-FR published an advisory regarding multiple vulnerabilities discovered in the Symfony framework. These vulnerabilities impact various components, including symfony/html-sanitizer, symfony/json-path, symfony/lox24-notifier, symfony/mailjet-mailer, symfony/mailtrap-mailer, symfony/mime, symfony/monolog-bridge, symfony/runtime, symfony/symfony, symfony/twilio-notifier and symfony/yaml. Exploitation of these vulnerabilities could allow an attacker to perform a remote denial of service (DoS), inject malicious code remotely (XSS), or perform Cross-Site Request Forgery (CSRF) attacks against users of a vulnerable application. The advisory lists versions prior to specific releases as vulnerable, depending on the component and branch (5.4.x, 6.4.x, 7.4.x, 8.0.x). These vulnerabilities pose a significant risk to applications built on the Symfony framework.

## Attack Chain

Given the variety of vulnerabilities, a generalized attack chain is presented:

1. An attacker identifies a Symfony application running a vulnerable version of a component like symfony/mime, or symfony/html-sanitizer.
2. The attacker crafts a malicious payload tailored to the specific vulnerability. For example, for XSS, this might involve injecting JavaScript into a field processed by the vulnerable component. For CSRF, this would be tricking the user into submitting a malicious request. For DoS, this could involve sending excessive data to exhaust resources.
3. The attacker delivers the payload to the Symfony application, potentially via a user-supplied input field, or directly through HTTP requests.
4. The vulnerable component processes the malicious payload. For example, the symfony/mime component may parse a malformed email, leading to a DoS.
5. The malicious payload is executed by the application. An XSS payload is executed within the user's browser context. A CSRF payload causes an unauthorized action to be performed on behalf of the user. A DoS payload causes the application to become unresponsive.
6. The attacker achieves their objective, such as gaining unauthorized access to user accounts through XSS, performing unauthorized actions through CSRF, or disrupting application availability through DoS.
7. Depending on the specific vulnerability and application, the attacker may chain multiple exploits to gain further access or control.

## Impact

Successful exploitation of these vulnerabilities can lead to a range of impacts, including denial of service, where the application becomes unavailable to legitimate users, cross-site scripting, which allows attackers to execute malicious JavaScript in the context of a user's browser, potentially leading to account compromise or data theft, and cross-site request forgery, which allows attackers to perform unauthorized actions on behalf of a user without their knowledge. The number of affected systems is potentially large, given the widespread use of the Symfony framework in web application development.

## Recommendation

*   Upgrade the affected Symfony components to the latest versions as specified in the Symfony security advisories GHSA-4qpc-3hr4-r2p4, GHSA-55rj-x2vc-4whq, GHSA-59f3-vp2f-mp9w, GHSA-64hg-93w9-fc35, GHSA-8v8v-g73j-492j, GHSA-9frc-8383-795m, GHSA-fqc7-9xjw-jrh3, GHSA-hhg7-c65m-h7ff, GHSA-m7v2-7gxm-vc2v, and GHSA-vqc8-7275-q272 to remediate the vulnerabilities.
*   Monitor web server logs for suspicious activity, such as unusual HTTP requests or patterns that may indicate exploitation attempts.
*   Deploy a web application firewall (WAF) with rules to detect and block common XSS and CSRF attacks, as these are potential vectors for exploiting the vulnerabilities.
*   Implement strict input validation and output encoding to prevent XSS vulnerabilities.
