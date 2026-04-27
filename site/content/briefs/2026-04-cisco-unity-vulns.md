---
title: Multiple Vulnerabilities in Cisco Unity Connection
slug: 2026-04-cisco-unity-vulns
description: Multiple vulnerabilities in Cisco Unity Connection can be exploited by an attacker to conduct cross-site scripting attacks, redirect users to malicious websites, manipulate data, and disclose confidential information.
date: "2026-04-16T11:13:57Z"
severities:
  - high
tags:
  - cisco
  - unity-connection
  - vulnerability
  - xss
  - data-manipulation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1149
rules:
  - title: Detect Suspicious URI parameters in Cisco Unity Connection
    description: Detects potential XSS or data manipulation attempts by identifying suspicious URI parameters in Cisco Unity Connection web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect POST requests to sensitive Cisco Unity Connection endpoints
    description: Detects potential attempts to manipulate data via POST requests to sensitive Cisco Unity Connection endpoints.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Cisco Unity Connection is susceptible to multiple vulnerabilities that can be exploited by malicious actors. Successful exploitation of these vulnerabilities could allow attackers to perform cross-site scripting (XSS) attacks, redirect users to attacker-controlled malicious websites, manipulate sensitive data, and achieve unauthorized disclosure of confidential information. The vulnerabilities affect Cisco Unity Connection, a unified communications platform. These vulnerabilities pose a…
