---
title: Langflow 1.3.0 Remote Code Execution Vulnerability
slug: 2026-05-langflow-rce
description: Langflow 1.3.0 contains a remote code execution vulnerability (CVE-2026-0770) due to untrusted input in the exec_globals parameter at the validate endpoint, allowing remote attackers to execute arbitrary code as root without authentication, as demonstrated by a public exploit.
date: "2026-05-29T08:21:41Z"
lastmod: "2026-07-21T15:00:09Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:langflow:langflow:1.4.2:-:*:*:*:*:*:*
tags:
  - remote-code-execution
  - webapps
  - langflow
vendors:
  - langflow
products:
  - langflow 1.3.0
  - langflow 1.2.0
  - Langflow < v1.9.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-0770
    cvss: 9.8
    epss: 0.10371
references:
  - https://www.exploit-db.com/exploits/52597
  - CVE-2026-0770
  - https://www.cve.org/CVERecord?id=CVE-2026-0770
rules:
  - title: Detect Langflow RCE via Validate Endpoint
    description: Detects CVE-2026-0770 exploitation — HTTP POST to /api/v1/validate/code endpoint with shell metacharacters in the code parameter indicating command injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-21T15:00:09Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-0770
---

A remote code execution (RCE) vulnerability exists in Langflow version 1.3.0, tracked as CVE-2026-0770. This flaw stems from the inclusion of functionality from an untrusted control sphere within the `exec_globals` parameter located at the `/api/v1/validate/code` endpoint. The vulnerability allows unauthenticated remote attackers to execute arbitrary code with root privileges on affected systems. Exploit-DB has published a working exploit (EDB-52597) for this vulnerability, which exacerbates the risk for organizations using unpatched instances of Langflow. Version 1.2.0 is also affected.

## Attack Chain

1.  The attacker sends an HTTP GET request to `/api/v1/auto_login` to obtain an access token.
2.  The server responds with a JSON object containing an `access_token`.
3.  The attacker crafts a malicious HTTP POST request to `/api/v1/validate/code` endpoint.
4.  The attacker sets the `Authorization` header with a `Bearare {access_token}` string.
5.  The request body contains a JSON object with a `code` parameter. This `code` parameter contains a Python script that leverages the `subprocess` module to execute arbitrary commands.
6.  The Python script within the `code` parameter utilizes `__import__('subprocess').run('%s', shell=True, capture_output=True, text=True)` to execute the attacker-controlled command.
7.  The server executes the attacker-supplied command with root privileges.
8.  The output of the command is returned to the attacker via the API response, confirming code execution.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary code with root privileges on the Langflow server. This can lead to complete system compromise, data theft, denial of service, or further lateral movement within the network. Given the nature of Langflow as a low-code framework designed for building flows with Large Language Models, such a compromise could lead to the exposure of sensitive LLM configurations, API keys, and data used within these flows.

## Recommendation

*   Apply the patch or upgrade to a secure version of Langflow to remediate CVE-2026-0770.
*   Deploy the Sigma rule `Detect Langflow RCE via Validate Endpoint` to detect exploitation attempts in web server logs.
*   Monitor network traffic for unusual POST requests to the `/api/v1/validate/code` endpoint containing shell metacharacters in the `code` parameter.
