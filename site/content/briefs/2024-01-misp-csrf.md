---
title: MISP Modules Website CSRF Vulnerability
slug: 2024-01-misp-csrf
description: A critical Cross-Site Request Forgery (CSRF) vulnerability in the MISP Modules website allows an attacker to induce an authenticated user to submit unintended requests to the home endpoint, potentially modifying session query data.
date: "2024-01-25T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - csrf
  - vulnerability
  - web-application
vendors:
  - MISP
products:
  - misp-modules (<= 3.0.7)
  - misp-modules website
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/advisories/GHSA-j4rh-7jcr-qm69
rules:
  - title: Detect Suspicious MISP Session Query Modification
    description: Detects potential exploitation attempts targeting the MISP Modules website by monitoring for unusual requests to the home endpoint that could modify session query data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST Requests to Home Endpoint Without Referer
    description: Detects potential CSRF attempts to the home endpoint by monitoring for POST requests without a referer header.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A Cross-Site Request Forgery (CSRF) vulnerability was discovered in the MISP Modules website affecting versions 3.0.7 and earlier. The vulnerability stems from the home blueprint lacking CSRF protection, which allows an attacker to craft malicious requests that are then executed by an authenticated user without their knowledge or consent. By exploiting this flaw, attackers can potentially modify session query data, leading to unauthorized actions or information disclosure within the context of the compromised user. This vulnerability was reported by Bilal Teke and has been addressed by enabling CSRF protection for the affected blueprint and hardening query parsing.

## Attack Chain

1. An attacker crafts a malicious HTML page containing a forged request targeting the MISP Modules website's home endpoint.
2. The attacker distributes the malicious HTML page through phishing, social engineering, or other means to a targeted, authenticated user of the MISP Modules website.
3. The victim visits the attacker-controlled webpage while authenticated to the MISP Modules website.
4. The victim's browser automatically sends the forged request to the MISP Modules website's home endpoint due to the missing CSRF protection.
5. The MISP Modules website processes the forged request as if it were a legitimate action initiated by the authenticated user.
6. The attacker leverages the forged request to modify session query data associated with the victim's session.
7. The modification of session query data leads to unintended behavior or access within the MISP Modules website, potentially allowing the attacker to gain unauthorized access or control.

## Impact

Successful exploitation of this CSRF vulnerability (CVE-2026-44364) could allow an attacker to modify session query data of authenticated users on the MISP Modules website. This could potentially lead to unauthorized access to sensitive information, modification of user settings, or execution of actions on behalf of the user. While the exact number of affected users is unknown, the critical severity suggests a high potential for widespread impact if the vulnerability were to be exploited in the wild.

## Recommendation

*   Upgrade to a patched version of `misp-modules` greater than 3.0.7 to remediate CVE-2026-44364.
*   Deploy the Sigma rule "Detect Suspicious MISP Session Query Modification" to identify potential exploitation attempts targeting the home endpoint by monitoring webserver logs.
*   Enable CSRF protection on all web application endpoints, following secure development practices.
