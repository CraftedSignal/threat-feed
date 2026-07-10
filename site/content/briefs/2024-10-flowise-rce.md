---
title: Flowise CSVAgent Authenticated Remote Code Execution
slug: 2024-10-flowise-rce
description: Flowise versions 3.0.13 and earlier are vulnerable to authenticated remote code execution due to missing sanitization in the CSVAgent component's customReadCSVFunc parameter, leading to arbitrary code injection and server compromise.
date: "2024-10-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - code-injection
  - rce
  - flowise
vendors:
  - Flowise
products:
  - Flowise
  - Flowise-components
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
references:
  - https://github.com/advisories/GHSA-9wc7-mj3f-74xv
rules:
  - title: Detect Flowise CSVAgent RCE Attempt via Malicious customReadCSV
    description: Detects potential RCE attempts in Flowise CSVAgent by identifying suspicious code-like strings within the customReadCSV parameter in POST requests to the /api/v1/chatflows endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Flowise Authentication Bypass Attempt
    description: 'Detects attempts to bypass Flowise authentication by checking for the `x-request-from: internal` header in requests to sensitive API endpoints.'
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Flowise, an open-source visual AI workflow tool, is vulnerable to a critical remote code execution (RCE) flaw in versions 3.0.13 and earlier. The vulnerability exists within the CSVAgent component, where the `customReadCSVFunc` parameter is not properly sanitized. This allows an authenticated attacker to inject arbitrary code into the `code` variable, which is then executed by the `pyodide` library on the server. The attack requires authentication but can be bypassed if `FLOWISE_USERNAME` and `FLOWISE_PASSWORD` are not set and the attacker provides the `"x-request-from": "internal"` header. Successful exploitation grants the attacker the ability to execute arbitrary commands on the underlying server, leading to a complete system compromise. The vulnerability was disclosed in GitHub Advisory GHSA-9wc7-mj3f-74xv.

## Attack Chain

1.  The attacker authenticates to the Flowise application, or bypasses authentication by setting the `x-request-from` header.
2.  The attacker crafts a malicious payload containing Python code for execution, embedding OS commands such as `whoami`. Example: `DataFrame({'foo': ['bar!']});import os;os.system('whoami')`.
3.  The attacker creates a new chat flow via a `POST` request to `/api/v1/chatflows`, including a CSVAgent node with the malicious payload in the `customReadCSV` field.
4.  The server saves the attacker-controlled `customReadCSV` code within the chat flow definition.
5.  The attacker triggers the execution of the crafted chat flow by sending a `POST` request to `/api/v1/prediction/[CHATFLOWID]`, which invokes the CSVAgent.
6.  The `pyodide.runPythonAsync` function executes the injected code due to insufficient sanitization of the `customReadCSV` input.
7.  The injected code executes arbitrary OS commands on the server.
8.  The attacker gains full control of the Flowise server.

## Impact

Successful exploitation of this vulnerability results in Remote Code Execution (RCE) on the Flowise server. This allows an attacker to execute arbitrary commands, potentially leading to complete system compromise. Affected versions include Flowise and Flowise-components up to and including version 3.0.13. The impact is critical, as it allows for unauthorized access and control of the server infrastructure.

## Recommendation

*   Upgrade Flowise and Flowise-components to a version higher than 3.0.13 to patch the vulnerability (GHSA-9wc7-mj3f-74xv).
*   Enforce strong authentication and authorization policies for the Flowise application to prevent unauthorized access and exploitation.
*   Deploy the Sigma rule `Detect Flowise CSVAgent RCE Attempt via Malicious customReadCSV` to identify exploitation attempts based on suspicious strings in HTTP request bodies targeting the `/api/v1/chatflows` endpoint.
*   Monitor web server logs for POST requests to `/api/v1/chatflows` and `/api/v1/prediction` with suspicious code-like strings in the request body, especially within the `customReadCSV` parameter.
