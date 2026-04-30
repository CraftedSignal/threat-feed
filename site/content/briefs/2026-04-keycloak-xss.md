---
title: Keycloak Cross-Site Scripting Vulnerability
slug: 2026-04-keycloak-xss
description: An authenticated remote attacker can exploit a vulnerability in Keycloak to perform a Cross-Site Scripting attack, potentially leading to unauthorized access and data compromise.
date: "2026-04-15T07:33:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - keycloak
  - xss
  - cross-site scripting
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1105
rules:
  - title: Detect Keycloak XSS Attempt via URI
    description: Detects potential XSS attempts in Keycloak by looking for common XSS patterns in the URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Keycloak XSS Attempt via HTTP POST
    description: Detects potential XSS attempts in Keycloak via HTTP POST requests containing script tags.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A Cross-Site Scripting (XSS) vulnerability exists within Keycloak, a widely-used open-source identity and access management solution. This vulnerability allows a remote, authenticated attacker to inject malicious scripts into web pages viewed by other users. The attacker must possess valid credentials to initially access the vulnerable Keycloak instance. While the specific version affected is not provided in this advisory, it's crucial for organizations using Keycloak to investigate and apply necessary patches or mitigations. The impact of successful exploitation ranges from defacement to sensitive data theft and account compromise. Defenders should prioritize patching Keycloak installations and implementing input validation to mitigate this risk.

## Attack Chain

1.  Attacker authenticates to the Keycloak instance with valid credentials.
2.  Attacker identifies a vulnerable input field or parameter within the Keycloak application (e.g., user profile, group name, etc.).
3.  Attacker crafts a malicious payload containing JavaScript code.
4.  Attacker injects the malicious payload into the vulnerable input field.
5.  The Keycloak application stores the malicious payload without proper sanitization.
6.  A victim user (e.g., another authenticated user or an administrator) accesses the page containing the injected payload.
7.  The victim's browser executes the malicious JavaScript code.
8.  The attacker can then steal cookies, redirect the user to a malicious site, or perform other actions on behalf of the victim.

## Impact

Successful exploitation of this XSS vulnerability can lead to several negative consequences. An attacker could potentially steal session cookies, allowing them to impersonate other users, including administrators. This could grant them unauthorized access to sensitive data, configuration settings, and management functions. Furthermore, the attacker could deface the Keycloak interface, inject phishing scams, or redirect users to malicious websites. The number of victims depends on the number of users accessing the page with the injected XSS payload.

## Recommendation

*   Implement input validation and output encoding to prevent XSS attacks within Keycloak.
*   Review Keycloak access logs for suspicious activity related to user profiles and injected scripts.
*   Deploy the Sigma rule to detect possible XSS attempts in Keycloak logs.
