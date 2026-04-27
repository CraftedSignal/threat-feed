---
title: Traefik ForwardAuth Authentication Bypass via X-Forwarded-Prefix Spoofing
slug: 2024-07-traefik-auth-bypass
description: A high-severity authentication bypass vulnerability exists in Traefik's `ForwardAuth` middleware when `trustForwardHeader=false` is configured and Traefik is deployed behind a trusted upstream proxy; Traefik fails to sanitize the `X-Forwarded-Prefix` header, allowing attackers to spoof a trusted prefix value and gain unauthorized access to protected backend routes.
date: "2024-07-03T12:00:00Z"
severities:
  - high
tags:
  - traefik
  - authentication-bypass
  - webserver
vendors:
  - Traefik
products:
  - Traefik
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-6384-m2mw-rf54
rules:
  - title: Detect Suspicious X-Forwarded-Prefix Header in Traefik Access Logs
    description: Detects requests with a suspicious X-Forwarded-Prefix header targeting the /forbidden path, potentially indicating an authentication bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious X-Forwarded-Prefix Value
    description: Detects requests containing '/admin' in the X-Forwarded-Prefix Header.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability impacts Traefik instances utilizing the `ForwardAuth` middleware with `trustForwardHeader=false`, when deployed behind a trusted upstream proxy. This vulnerability arises from Traefik's failure to properly sanitize the `X-Forwarded-Prefix` header. Although Traefik correctly rebuilds other `X-Forwarded-*` headers like `X-Forwarded-For` and `X-Forwarded-Host`, it does not strip or rebuild `X-Forwarded-Prefix`. An attacker can inject a malicious…
