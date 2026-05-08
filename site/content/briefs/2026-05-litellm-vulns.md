---
title: LiteLLM Multiple Vulnerabilities
slug: 2026-05-litellm-vulns
description: Multiple vulnerabilities in LiteLLM could allow an attacker to perform a SQL injection attack and gain unauthorized access or execute arbitrary code with the privileges of the service.
date: "2026-05-08T10:11:53Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - privilege-escalation
vendors:
  - LiteLLM
products:
  - LiteLLM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1288
rules:
  - title: Detect Suspicious LiteLLM SQL Injection Attempts
    description: Detects suspicious SQL injection attempts targeting LiteLLM instances by identifying common SQL injection payloads in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious LiteLLM Code Execution via Web Shell
    description: Detects possible code execution attempts via web shells dropped into the LiteLLM web directory.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in LiteLLM that could be exploited by an attacker to perform SQL injection attacks and gain unauthorized access to sensitive data or execute arbitrary code with the privileges of the LiteLLM service. This poses a significant risk as successful exploitation could lead to complete system compromise, data breaches, or other malicious activities. The vulnerabilities could be exploited by sending malicious requests to the LiteLLM instance. Defenders should prioritize patching and implementing mitigations to prevent potential attacks.

## Attack Chain

1. Attacker identifies a SQL injection vulnerability in a LiteLLM endpoint.
2. Attacker crafts a malicious SQL query designed to exploit the vulnerability.
3. The malicious SQL query is sent to the vulnerable LiteLLM endpoint as part of a crafted HTTP request.
4. LiteLLM processes the malicious query without proper sanitization, leading to SQL injection.
5. The attacker gains unauthorized access to the underlying database.
6. The attacker escalates privileges within the database by injecting code to create a new administrator account or modify existing permissions.
7. The attacker uses the elevated privileges to access sensitive data stored in the database, such as user credentials, API keys, or proprietary information.
8. Alternatively, the attacker may inject arbitrary code to be executed by the LiteLLM service, leading to arbitrary code execution.

## Impact

Successful exploitation of these vulnerabilities in LiteLLM could allow attackers to gain unauthorized access to sensitive data, including user credentials and proprietary information. It could also enable them to execute arbitrary code with the privileges of the LiteLLM service, leading to a complete compromise of the system. The lack of specific victim counts or sector targeting information makes it difficult to quantify the full impact, but the potential for widespread damage is significant.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious LiteLLM SQL Injection Attempts` to identify potential SQL injection attacks targeting LiteLLM instances.
*   Review and harden LiteLLM input validation and sanitization routines to prevent SQL injection vulnerabilities.
*   Monitor web server logs for suspicious HTTP requests targeting LiteLLM endpoints, as described in the attack chain.
