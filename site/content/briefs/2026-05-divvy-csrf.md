---
title: DivvyDrive Cross-Site Request Forgery Vulnerability (CVE-2026-5791)
slug: 2026-05-divvy-csrf
description: DivvyDrive versions 4.8.2.9 through 4.8.3.2 are susceptible to cross-site request forgery (CSRF), allowing an attacker to execute unauthorized actions on behalf of an authenticated user.
date: "2026-05-07T13:16:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csrf
  - web-application
  - vulnerability
vendors:
  - DivvyDrive Information Technologies Inc.
products:
  - DivvyDrive (4.8.2.9 to < 4.8.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5791
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5791
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0182
rules:
  - title: Detect Potential CSRF Attempts via Referer Header
    description: This rule detects potential Cross-Site Request Forgery (CSRF) attempts by identifying HTTP POST requests with a missing or unusual Referer header. CSRF attacks often involve submitting requests from a different origin than the target website, which can be indicated by the absence or manipulation of the Referer header.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests from Unexpected Domains
    description: This rule identifies HTTP POST requests originating from domains different from the expected server domain. This can indicate CSRF attacks or other malicious activity where requests are being forged from external sources.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

DivvyDrive, a product of DivvyDrive Information Technologies Inc., is vulnerable to a Cross-Site Request Forgery (CSRF) vulnerability, identified as CVE-2026-5791. This flaw exists in versions 4.8.2.9 up to, but not including, version 4.8.3.2. CSRF vulnerabilities allow attackers to trick users into performing actions they did not intend to, potentially leading to unauthorized modifications or data breaches. Successful exploitation requires an authenticated user to interact with a malicious link or website controlled by the attacker. This could have serious implications for data security and integrity within organizations using affected versions of DivvyDrive.

## Attack Chain

1.  The attacker crafts a malicious HTML page containing a forged request targeting a DivvyDrive function, such as changing a user's password or modifying data.
2.  The attacker distributes the malicious HTML page via email or other means, enticing a DivvyDrive user to visit the page while logged into their DivvyDrive account.
3.  The user, while authenticated to DivvyDrive, visits the attacker-controlled webpage.
4.  The malicious page automatically sends a request to the DivvyDrive server, appearing as if it originated from the logged-in user.
5.  The DivvyDrive server, lacking proper CSRF protection, processes the request as a legitimate action from the authenticated user.
6.  The attacker's desired action is executed on the DivvyDrive server, potentially modifying user settings, data, or other system configurations.
7.  The impact could be privilege escalation, data manipulation, or account compromise depending on the targeted function.

## Impact

Successful exploitation of CVE-2026-5791 allows an attacker to perform actions as an authenticated user without their knowledge or consent. Depending on the targeted DivvyDrive functionality, this could lead to unauthorized data modification, privilege escalation, or complete account compromise. The severity is rated as critical with a CVSS v3.1 score of 9.6, highlighting the potential for significant impact. Organizations using vulnerable versions of DivvyDrive are at risk of data breaches and unauthorized system modifications.

## Recommendation

*   Upgrade DivvyDrive to version 4.8.3.2 or later to remediate CVE-2026-5791 as mentioned in the overview.
*   Deploy the Sigma rule "Detect Potential CSRF Attempts via Referer Header" to identify suspicious requests lacking a proper Referer header, a common characteristic of CSRF attacks.
*   Enable web server logging and monitor for POST requests originating from unexpected domains as covered by the Sigma rule.
