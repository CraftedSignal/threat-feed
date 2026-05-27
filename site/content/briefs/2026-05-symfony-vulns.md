---
title: Multiple Vulnerabilities in Symfony Framework
slug: 2026-05-symfony-vulns
description: Multiple vulnerabilities in Symfony, including SSRF, XSS, and security policy bypass, can be exploited by an attacker to compromise the application.
date: "2026-05-27T14:32:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - symfony
  - vulnerability
  - ssrf
  - xss
  - security-policy-bypass
vendors:
  - Symfony
products:
  - Symfony < 5.4.53
  - Symfony < 6.4.41
  - Symfony < 7.0.13
  - Symfony < 8.0.13
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0653/
  - https://github.com/symfony/symfony/security/advisories/GHSA-38cx-cq6f-5755
  - https://github.com/symfony/symfony/security/advisories/GHSA-6h46-9jf5-q59x
  - https://github.com/symfony/symfony/security/advisories/GHSA-h5x3-xfc9-m39h
  - https://github.com/symfony/symfony/security/advisories/GHSA-rrj9-5q2j-4gvr
  - https://github.com/symfony/symfony/security/advisories/GHSA-v3wm-qf9p-c549
  - https://github.com/symfony/symfony/security/advisories/GHSA-x5qj-865h-mgvm
  - https://www.cve.org/CVERecord?id=CVE-2026-48489
  - https://www.cve.org/CVERecord?id=CVE-2026-48736
  - https://www.cve.org/CVERecord?id=CVE-2026-48747
  - https://www.cve.org/CVERecord?id=CVE-2026-48760
  - https://www.cve.org/CVERecord?id=CVE-2026-48761
  - https://www.cve.org/CVERecord?id=CVE-2026-48784
rules:
  - title: Detects CVE-2026-48489 Exploitation Attempt — Suspicious SSRF Attempt
    description: Detects CVE-2026-48489 exploitation attempt — Monitors web server logs for requests containing potentially malicious URLs indicative of SSRF attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-48736 Exploitation Attempt — Suspicious XSS Attempt
    description: Detects CVE-2026-48736 exploitation attempt — Monitors web server logs for requests containing common XSS payloads.
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

Multiple vulnerabilities have been discovered in the Symfony framework, a popular PHP web application framework. These vulnerabilities, disclosed in Symfony security advisories GHSA-38cx-cq6f-5755, GHSA-6h46-9jf5-q59x, GHSA-h5x3-xfc9-m39h, GHSA-rrj9-5q2j-4gvr, GHSA-v3wm-qf9p-c549, and GHSA-x5qj-865h-mgvm, can allow an attacker to perform server-side request forgery (SSRF), inject malicious code via cross-site scripting (XSS), and bypass security policies implemented within the application. The vulnerabilities affect Symfony versions prior to 5.4.53, 6.4.41, 7.0.13 and 8.0.13. Successful exploitation of these vulnerabilities could lead to data theft, unauthorized access, or complete compromise of the affected application and its underlying infrastructure.

## Attack Chain

1.  The attacker identifies a Symfony application running a vulnerable version.
2.  The attacker crafts a malicious request targeting a specific endpoint vulnerable to SSRF (CVE-2026-48489), XSS (CVE-2026-48736), or security policy bypass (CVE-2026-48747, CVE-2026-48760, CVE-2026-48761, CVE-2026-48784).
3.  For SSRF, the attacker manipulates request parameters to force the server to make requests to internal or external resources, potentially exposing sensitive information.
4.  For XSS, the attacker injects malicious JavaScript code into the application's response, which is then executed in the victim's browser, potentially stealing cookies or redirecting the user to a malicious site.
5.  For security policy bypass, the attacker exploits flaws in the application's access control mechanisms to gain unauthorized access to restricted resources or functionalities.
6.  The attacker leverages the compromised application to gain further access to the internal network.
7.  The attacker exfiltrates sensitive data or performs other malicious activities.

## Impact

Successful exploitation of these vulnerabilities could result in a range of impacts, including the exposure of sensitive data, unauthorized access to restricted resources, and complete compromise of the affected Symfony application. The severity of the impact will depend on the specific vulnerability exploited and the configuration of the affected application. Organizations using vulnerable versions of Symfony are at risk of data breaches, financial losses, and reputational damage.

## Recommendation

*   Upgrade Symfony to the latest patched version to address the vulnerabilities (see Symfony security advisories GHSA-38cx-cq6f-5755, GHSA-6h46-9jf5-q59x, GHSA-h5x3-xfc9-m39h, GHSA-rrj9-5q2j-4gvr, GHSA-v3wm-qf9p-c549, and GHSA-x5qj-865h-mgvm).
*   Deploy the following Sigma rules to your SIEM to detect potential exploitation attempts.
*   Monitor web server logs for suspicious activity, such as unexpected requests to internal resources or the presence of malicious JavaScript code in HTTP responses.
*   Review and harden security policies to prevent unauthorized access to sensitive resources.
