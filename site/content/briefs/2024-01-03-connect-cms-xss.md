---
title: Connect-CMS Cabinet Plugin DOM-based XSS Vulnerability
slug: 2024-01-03-connect-cms-xss
description: A DOM-based Cross-Site Scripting (XSS) vulnerability exists in the Cabinet Plugin list view of Connect-CMS, affecting versions 1.35.0 to 1.41.0 and 2.35.0 to 2.41.0, which can lead to arbitrary script execution in the victim's browser.
date: "2026-03-23T20:35:48Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - xss
  - connect-cms
  - cabinet-plugin
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/advisories/GHSA-cmfh-mpmf-fmq4
rules:
  - title: Detect Suspicious URI Access to Cabinet Plugin
    description: Detects access to the Cabinet Plugin with potentially malicious parameters indicative of XSS attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1055
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests to Cabinet Plugin with Suspicious Payloads
    description: Detects POST requests to the Cabinet Plugin that contain common XSS payloads in the request body, potentially indicating an XSS attack.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1055
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A DOM-based Cross-Site Scripting (XSS) vulnerability has been identified in the Cabinet Plugin of Connect-CMS. This vulnerability affects versions 1.35.0 through 1.41.0 of the 1.x series and versions 2.35.0 through 2.41.0 of the 2.x series. Discovered by Sho Odagiri of GMO Cybersecurity by Ierae, Inc., the flaw resides in the Cabinet Plugin's list view, stemming from the rendering of saved names. Exploitation requires an attacker to authenticate and access the affected functionality. Successful exploitation allows arbitrary script execution within the victim's browser, potentially leading to unauthorized actions, such as session hijacking, or information theft. Organizations using the Connect-CMS Cabinet Plugin are urged to update to versions 1.41.1 or 2.41.1 to mitigate this risk.

## Attack Chain

1.  Attacker authenticates to the Connect-CMS application with valid credentials.
2.  Attacker navigates to the Cabinet Plugin list view.
3.  Attacker crafts a malicious payload containing JavaScript code.
4.  Attacker saves a new cabinet or modifies an existing cabinet's name, injecting the malicious payload into the name field.
5.  The application saves the cabinet name with the injected XSS payload.
6.  When a victim user views the Cabinet Plugin list view, the malicious payload is rendered in their browser without proper sanitization.
7.  The victim's browser executes the injected JavaScript code.
8.  The attacker gains the ability to perform actions on behalf of the victim, such as stealing cookies or redirecting to a malicious website.

## Impact

Successful exploitation of this XSS vulnerability can allow an attacker to execute arbitrary JavaScript code in the victim's browser. This could lead to session hijacking, where the attacker gains control of the victim's account. Sensitive information, such as authentication tokens or personal data, could be stolen. The attacker could also redirect the victim to a phishing site or deface the Connect-CMS installation.

## Recommendation

*   Upgrade Connect-CMS to version 1.41.1 or 2.41.1 to patch the XSS vulnerability (CVE-2026-32277).
*   Implement a Web Application Firewall (WAF) rule to detect and block common XSS payloads in requests to the Cabinet Plugin list view.
*   Enable strict Content Security Policy (CSP) headers to prevent the execution of inline JavaScript and mitigate the impact of potential XSS attacks.
*   Implement input validation and output encoding on the Cabinet Plugin's name field to prevent the injection of malicious code.
