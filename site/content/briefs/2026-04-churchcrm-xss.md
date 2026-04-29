---
title: ChurchCRM Stored XSS Vulnerability in Person Property Management
slug: 2026-04-churchcrm-xss
description: A stored cross-site scripting (XSS) vulnerability in ChurchCRM versions prior to 7.0.0 allows authenticated users to inject arbitrary JavaScript code via dynamically assigned person properties, leading to potential session hijacking or account compromise when other users view the affected profile.
date: "2026-04-08T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - xss
  - web-application
  - churchcrm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2023-38766
    cvss: 5.4
    epss: 0.00209
  - id: CVE-2026-35576
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35576
rules:
  - title: Detect ChurchCRM XSS Attempt via Property Value
    description: Detects potential XSS attacks in ChurchCRM by monitoring for script tags or event handlers within dynamically assigned person property values.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM XSS in HTTP Response
    description: Detects potential XSS attacks in ChurchCRM reflected in the HTTP response body. This rule is looking for responses containing script tags or event handlers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is vulnerable to a stored cross-site scripting (XSS) attack affecting versions prior to 7.0.0. This vulnerability resides within the Person Property Management subsystem and stems from insufficient input sanitization when handling dynamically assigned person properties. An authenticated attacker can inject malicious JavaScript code, which is then persistently stored in the database. When other users view the compromised person's profile or access the printable view of that profile, the injected script executes, potentially leading to session hijacking or complete account takeover. This issue impacts versions patched for CVE-2023-38766, highlighting a persistent weakness. Organizations using vulnerable versions of ChurchCRM are at risk of unauthorized access and data breaches. Users are advised to update to version 7.0.0 or later to remediate this vulnerability.

## Attack Chain

1. Attacker authenticates to ChurchCRM with valid user credentials.
2. Attacker navigates to the Person Property Management section.
3. Attacker creates or modifies a dynamically assigned person property, injecting malicious JavaScript code into a property field. Example payload: `<script>alert("XSS")</script>`.
4. The application stores the malicious payload in the database without proper sanitization.
5. A different user views the profile of the person with the compromised property.
6. The stored XSS payload is rendered within the user's browser, executing the injected JavaScript code.
7. The attacker's JavaScript code steals the user's session cookie or redirects the user to a phishing page.
8. The attacker uses the stolen session cookie to hijack the user's session and gain unauthorized access to the application, potentially escalating privileges and accessing sensitive data.

## Impact

Successful exploitation of this stored XSS vulnerability can lead to session hijacking and full account compromise. Attackers could gain unauthorized access to sensitive church member data, modify records, or perform administrative functions within the ChurchCRM system. The impact ranges from data theft and privacy breaches to complete disruption of church management operations. Given the potential for widespread access to sensitive personal information, organizations are strongly advised to apply the necessary updates to mitigate this risk. The CVSS v3.1 base score for this vulnerability is 8.7, indicating a high severity.

## Recommendation

*   Upgrade ChurchCRM to version 7.0.0 or later to patch the vulnerability (CVE-2026-35576).
*   Deploy the provided Sigma rule to detect potential XSS attempts via crafted property values.
*   Review and audit existing dynamically assigned person properties for suspicious script tags to identify potentially compromised records.
*   Implement input validation and output encoding to prevent future XSS vulnerabilities in ChurchCRM.
