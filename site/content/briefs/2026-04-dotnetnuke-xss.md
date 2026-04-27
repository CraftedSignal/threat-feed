---
title: DotNetNuke.Core Stored XSS via SVG Upload
slug: 2026-04-dotnetnuke-xss
description: DotNetNuke.Core is vulnerable to stored cross-site scripting (XSS) where a user can upload a specially crafted SVG file containing malicious scripts, potentially targeting both authenticated and unauthenticated DNN users, with successful exploitation requiring user interaction and leading to high impact on confidentiality, integrity, and availability.
date: "2026-04-11T12:00:00Z"
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

DotNetNuke.Core versions prior to 10.2.2 are vulnerable to stored cross-site scripting (XSS). An attacker can exploit this vulnerability by uploading a malicious SVG file to the DotNetNuke server. This file contains embedded JavaScript that executes when the SVG is processed and displayed by the application. Successful exploitation requires a user to interact with the uploaded SVG file, which then triggers the malicious script execution. This poses a significant risk as the injected scripts can…
