---
title: LiteLLM Proxy API Key Verification SQL Injection
slug: 2024-11-litellm-sqli
description: A SQL injection vulnerability exists in LiteLLM versions 1.81.16 to prior to 1.83.7 allowing an unauthenticated attacker to inject SQL queries via a crafted 'Authorization' header, potentially leading to unauthorized data access or modification.
date: "2024-11-08T12:00:00Z"
severities:
  - critical
tags:
  - sqli
  - litellm
  - web-application
vendors:
  - pip
products:
  - litellm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-r75f-5x8p-qvmc
rules:
  - title: Detect LiteLLM SQL Injection Attempt via Authorization Header
    description: Detects potential SQL injection attempts in the Authorization header of HTTP requests targeting LiteLLM servers.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LiteLLM SQL Injection Attempt via Authorization Header - Error Based
    description: Detects potential error-based SQL injection attempts in the Authorization header of HTTP requests targeting LiteLLM servers.
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

A critical SQL injection vulnerability has been identified in LiteLLM, specifically affecting versions 1.81.16 through 1.83.6. The vulnerability resides within the proxy API key verification process. Due to improper sanitization of the `Authorization` header, an unauthenticated attacker can inject arbitrary SQL commands. This is achieved by sending a specially crafted header to any LLM API route, such as `POST /chat/completions`, which triggers the vulnerable query through the proxy's…
