---
title: Znuny Cross-Site Scripting Vulnerability
slug: 2026-03-znuny-xss
description: An anonymous remote attacker can exploit a vulnerability in Znuny to perform a cross-site scripting attack, potentially leading to information disclosure or session hijacking.
date: "2026-03-24T10:35:57Z"
severities:
  - medium
tags:
  - znuny
  - xss
  - cross-site scripting
  - web application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0826
rules:
  - title: Detect Suspicious Znuny URL Parameters
    description: Detects potential XSS attempts in Znuny URL parameters based on common XSS payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Znuny Process Outbound Network Activity
    description: Detects outbound network connections from the Znuny process, which might indicate post-exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A vulnerability exists in Znuny, a web-based ticketing system, that can be exploited by an unauthenticated, remote attacker. The specific nature of the vulnerability is Cross-Site Scripting (XSS). Successful exploitation could allow the attacker to inject malicious scripts into the web pages served by Znuny. These scripts could then be executed in the context of other users' browsers, potentially leading to session hijacking, information disclosure, or defacement of the Znuny interface. Given…
