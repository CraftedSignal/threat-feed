---
title: Keycloak Cross-Site Scripting Vulnerability
slug: 2026-04-keycloak-xss
description: An authenticated remote attacker can exploit a vulnerability in Keycloak to perform a Cross-Site Scripting attack, potentially leading to unauthorized access and data compromise.
date: "2026-04-15T07:33:56Z"
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

A Cross-Site Scripting (XSS) vulnerability exists within Keycloak, a widely-used open-source identity and access management solution. This vulnerability allows a remote, authenticated attacker to inject malicious scripts into web pages viewed by other users. The attacker must possess valid credentials to initially access the vulnerable Keycloak instance. While the specific version affected is not provided in this advisory, it's crucial for organizations using Keycloak to investigate and apply…
