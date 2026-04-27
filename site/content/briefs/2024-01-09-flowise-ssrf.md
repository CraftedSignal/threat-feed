---
title: Flowise SSRF Protection Bypass via Unprotected Built-in HTTP Modules
slug: 2024-01-09-flowise-ssrf
description: Flowise is vulnerable to SSRF protection bypass via unprotected built-in HTTP modules in the custom function sandbox, allowing authenticated users to access internal network resources by exploiting the lack of SSRF protection on Node.js `http`, `https`, and `net` modules.
date: "2026-04-16T21:50:12Z"
severities:
  - high
tags:
  - ssrf
  - flowise
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-xhmj-rg95-44hv
rules:
  - title: Flowise SSRF Using HTTP Module
    description: Detects SSRF attempts in Flowise by monitoring for HTTP requests originating from the custom function feature that target cloud metadata endpoints using the built-in http module.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Flowise Custom Function Execution with Network Activity
    description: Detects the execution of custom functions in Flowise that results in network connections, which may indicate SSRF attempts or other malicious activities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Flowise, a low-code platform for building custom automation workflows, is susceptible to a Server-Side Request Forgery (SSRF) protection bypass. This vulnerability stems from the application's incomplete implementation of SSRF defenses. While `axios` and `node-fetch` libraries are secured with an `HTTP_DENY_LIST`, the built-in Node.js modules `http`, `https`, and `net` are permitted within the NodeVM sandbox without any equivalent restrictions. An authenticated attacker can exploit this…
