---
title: Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerabilities
slug: 2026-05-cisco-ise-xss
description: Multiple stored cross-site scripting (XSS) vulnerabilities in the web-based management interface of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to inject malicious code into specific pages of the interface, leading to arbitrary script execution or sensitive information access.
date: "2026-05-05T18:21:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - cisco
  - web-application
vendors:
  - Cisco
products:
  - Identity Services Engine
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-20204
    cvss: 4.8
    epss: 0.00048
  - id: CVE-2025-20205
    cvss: 4.8
    epss: 0.00031
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-42tgsdMG
rules:
  - title: Detect Cisco ISE XSS Attempt via HTTP Request
    description: Detects potential XSS attempts against Cisco ISE web interface by looking for script tags and event handlers in HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Cisco ISE XSS Attempt via HTTP Body
    description: Detects potential XSS attempts against Cisco ISE web interface by looking for script tags and event handlers in HTTP request body.
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

Cisco Identity Services Engine (ISE) is susceptible to stored cross-site scripting (XSS) vulnerabilities within its web-based management interface. Disclosed on May 5, 2026, these flaws stem from insufficient validation of user-supplied input. An attacker with valid administrative credentials can inject malicious code into specific pages of the ISE interface. Successful exploitation allows the attacker to execute arbitrary script code within the context of the interface or access sensitive browser-based information. These vulnerabilities pose a risk to the confidentiality and integrity of the ISE system and the data it manages, requiring immediate patching.

## Attack Chain

1. An attacker obtains valid administrative credentials for the Cisco ISE web-based management interface, potentially through credential theft or social engineering.
2. The attacker logs into the ISE web-based management interface.
3. The attacker navigates to a specific page within the interface that is vulnerable to stored XSS (CVE-2025-20204, CVE-2025-20205).
4. The attacker injects malicious JavaScript code into a field that is not properly validated. This could be a configuration setting, a user profile, or any other editable field.
5. The malicious code is stored within the ISE system's database or configuration files.
6. A legitimate administrator or user accesses the page containing the stored XSS payload.
7. The malicious JavaScript code is executed within the user's browser, in the context of the ISE web interface.
8. The attacker can now perform actions such as stealing cookies, redirecting the user to a malicious website, or modifying the content of the ISE interface.

## Impact

Successful exploitation of these XSS vulnerabilities can compromise the confidentiality and integrity of the Cisco ISE system. An attacker could potentially gain unauthorized access to sensitive information, such as network configurations, user credentials, and security policies. They could also modify the ISE interface to phish for credentials or redirect users to malicious websites. Given the central role of ISE in network access control, these vulnerabilities could have a significant impact on the security of the entire network.

## Recommendation

*   Apply the software updates released by Cisco to address CVE-2025-20204 and CVE-2025-20205 on all affected Cisco Identity Services Engine (ISE) instances.
*   Deploy the Sigma rule "Detect Cisco ISE XSS Attempt via HTTP Request" to your SIEM to identify potential exploitation attempts targeting the web interface.
*   Review and enforce strong password policies for all administrative accounts on Cisco ISE to reduce the risk of credential compromise.
*   Monitor web server logs for suspicious activity, particularly requests containing potentially malicious JavaScript code, to identify and investigate potential XSS attacks.
