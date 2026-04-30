---
title: DotNetNuke.Core Stored XSS via SVG Upload
slug: 2026-04-dotnetnuke-xss
description: DotNetNuke.Core is vulnerable to stored cross-site scripting (XSS) where a user can upload a specially crafted SVG file containing malicious scripts, potentially targeting both authenticated and unauthenticated DNN users, with successful exploitation requiring user interaction and leading to high impact on confidentiality, integrity, and availability.
date: "2026-04-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dotnetnuke
  - xss
  - svg
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://github.com/advisories/GHSA-ffq7-898w-9jc4
  - https://github.com/dnnsoftware/Dnn.Platform/releases/tag/v10.2.2
rules:
  - title: Detect SVG Upload with Embedded JavaScript
    description: Detects attempts to upload SVG files containing embedded JavaScript code, which is a common technique for exploiting XSS vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - file_event
      - windows|linux
  - title: Detect HTTP Request to SVG file containing JavaScript
    description: Detects HTTP request to a SVG file containing javascript code.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux|windows
rules_count: 2
---

DotNetNuke.Core versions prior to 10.2.2 are vulnerable to stored cross-site scripting (XSS). An attacker can exploit this vulnerability by uploading a malicious SVG file to the DotNetNuke server. This file contains embedded JavaScript that executes when the SVG is processed and displayed by the application. Successful exploitation requires a user to interact with the uploaded SVG file, which then triggers the malicious script execution. This poses a significant risk as the injected scripts can target both authenticated and unauthenticated users, potentially leading to session hijacking, data theft, or unauthorized actions performed on behalf of the victim. This vulnerability was published on April 10, 2026, and patched in version 10.2.2.

## Attack Chain

1. An attacker crafts a malicious SVG file containing embedded JavaScript code designed for XSS exploitation.
2. The attacker, with low privileges, uploads the malicious SVG file to the DotNetNuke server through a file upload functionality.
3. The server stores the SVG file, making it accessible to other users.
4. A user (either authenticated or unauthenticated) navigates to the location where the SVG file is stored or displayed.
5. The user's browser processes the SVG file, triggering the execution of the embedded JavaScript.
6. The malicious script executes within the user's browser session, gaining access to cookies, session tokens, and other sensitive information.
7. The attacker steals user's cookies and session tokens.
8. The attacker uses stolen session tokens to hijack the user's session, perform unauthorized actions, and potentially escalate privileges.

## Impact

Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code within the context of a user's session. This can lead to sensitive information disclosure, such as stealing user credentials or session cookies. An attacker can then hijack user sessions, perform unauthorized actions on their behalf, and potentially gain elevated privileges within the DotNetNuke application. Due to the nature of stored XSS, the impact can be widespread, affecting any user who interacts with the malicious SVG file until the vulnerability is patched.

## Recommendation

*   Upgrade DotNetNuke.Core to version 10.2.2 or later to patch the XSS vulnerability (reference: Affected versions).
*   Implement server-side validation to sanitize uploaded SVG files and prevent the injection of malicious scripts (reference: Description).
*   Deploy the Sigma rule provided below to detect attempts to upload SVG files containing JavaScript code (reference: Sigma rule "Detect SVG Upload with Embedded JavaScript").
*   Configure web application firewalls (WAFs) to inspect and block suspicious SVG uploads based on content analysis (reference: Description).
*   Enable logging for file uploads to track potential malicious activity (reference: logsource category "file_event").
