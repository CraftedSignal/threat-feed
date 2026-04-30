---
title: LiteLLM Proxy API Key Verification SQL Injection
slug: 2024-11-litellm-sqli
description: A SQL injection vulnerability exists in LiteLLM versions 1.81.16 to prior to 1.83.7 allowing an unauthenticated attacker to inject SQL queries via a crafted 'Authorization' header, potentially leading to unauthorized data access or modification.
date: "2024-11-08T12:00:00Z"
type: advisory
types:
  - advisory
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

A critical SQL injection vulnerability has been identified in LiteLLM, specifically affecting versions 1.81.16 through 1.83.6. The vulnerability resides within the proxy API key verification process. Due to improper sanitization of the `Authorization` header, an unauthenticated attacker can inject arbitrary SQL commands. This is achieved by sending a specially crafted header to any LLM API route, such as `POST /chat/completions`, which triggers the vulnerable query through the proxy's error-handling mechanism. Defenders should prioritize patching to version 1.83.7 or later to mitigate this risk, or implement the suggested workaround.

## Attack Chain

1.  The attacker sends a crafted HTTP `Authorization` header to a LiteLLM API endpoint (e.g., `/chat/completions`).
2.  The LiteLLM proxy receives the request and extracts the API key from the `Authorization` header.
3.  Due to insufficient sanitization, the API key value is directly concatenated into a SQL query string.
4.  The vulnerable SQL query is executed against the proxy's database.
5.  The attacker injects SQL code to read sensitive data, such as user credentials or API keys, from the database.
6.  The attacker may further inject SQL code to modify data, potentially granting themselves administrative privileges or compromising other users' accounts.
7.  The attacker gains unauthorized access to the LiteLLM proxy.
8.  The attacker leverages the compromised proxy to access and control connected LLMs, exfiltrate data, or disrupt services.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to complete compromise of the LiteLLM proxy. Attackers could read or modify sensitive data within the proxy's database, including API keys and credentials. This could lead to unauthorized access to managed LLMs and potentially allow attackers to exfiltrate sensitive data, disrupt services, or gain a foothold for further attacks within the compromised environment. The impact is significant due to the potential for widespread data breaches and service disruptions.

## Recommendation

*   Upgrade LiteLLM to version 1.83.7 or later to patch the SQL injection vulnerability as detailed in the advisory [GHSA-r75f-5x8p-qvmc](https://github.com/advisories/GHSA-r75f-5x8p-qvmc).
*   If upgrading is not immediately feasible, set `disable_error_logs: true` in the `general_settings` configuration to mitigate the risk as described in the advisory [GHSA-r75f-5x8p-qvmc](https://github.com/advisories/GHSA-r75f-5x8p-qvmc).
*   Monitor web server logs for suspicious `Authorization` headers containing SQL injection payloads to detect potential exploitation attempts. Deploy the provided Sigma rule targeting HTTP request patterns.
