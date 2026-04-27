---
title: Connect-CMS Cabinet Plugin DOM-based XSS Vulnerability
slug: 2024-01-03-connect-cms-xss
description: A DOM-based Cross-Site Scripting (XSS) vulnerability exists in the Cabinet Plugin list view of Connect-CMS, affecting versions 1.35.0 to 1.41.0 and 2.35.0 to 2.41.0, which can lead to arbitrary script execution in the victim's browser.
date: "2026-03-23T20:35:48Z"
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

A DOM-based Cross-Site Scripting (XSS) vulnerability has been identified in the Cabinet Plugin of Connect-CMS. This vulnerability affects versions 1.35.0 through 1.41.0 of the 1.x series and versions 2.35.0 through 2.41.0 of the 2.x series. Discovered by Sho Odagiri of GMO Cybersecurity by Ierae, Inc., the flaw resides in the Cabinet Plugin's list view, stemming from the rendering of saved names. Exploitation requires an attacker to authenticate and access the affected functionality. Successful…
