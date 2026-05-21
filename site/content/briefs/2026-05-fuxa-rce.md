---
title: FUXA 1.2.9 Unauthenticated Remote Code Execution
slug: 2026-05-fuxa-rce
description: A remote code execution (RCE) vulnerability exists in FUXA version 1.2.9 and earlier due to an unauthenticated path traversal issue in the /api/upload endpoint, allowing attackers to write arbitrary files and execute code.
date: "2026-05-21T13:32:38Z"
type: threat
types:
  - threat
severities:
  - critical
cpes:
  - cpe:2.3:a:frangoteam:fuxa:*:*:*:*:*:*:*:*
tags:
  - rce
  - path traversal
  - cve-2026-25895
  - fuxa
vendors:
  - frangoteam
products:
  - FUXA
affected_os:
  - Ubuntu Server
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-25895
    cvss: 9.8
    epss: 0.0007
references:
  - https://www.exploit-db.com/exploits/52568
  - CVE-2026-25895
rules:
  - title: Detect CVE-2026-25895 Exploitation — FUXA Unauthenticated Path Traversal
    description: Detects CVE-2026-25895 exploitation — HTTP POST to /api/upload with path traversal sequences in the destination parameter, indicating a path traversal attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1566.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-25895 Exploitation - FUXA Settings.js Overwrite
    description: Detects CVE-2026-25895 exploitation - Detects the creation or modification of settings.js with suspicious content in FUXA
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

FUXA version 1.2.9 and earlier is vulnerable to an unauthenticated remote code execution (RCE) vulnerability, tracked as CVE-2026-25895. The vulnerability stems from a path traversal flaw in the `/api/upload` endpoint, which lacks proper authentication and input validation. An attacker can exploit this vulnerability to write arbitrary files to the server, potentially leading to code execution. Publicly available exploit code (EDB-52568) increases the risk to unpatched FUXA instances. The vulnerability exists because the `/api/upload` route is registered without authentication middleware. The `destination` parameter in the JSON body is concatenated into a file path without sufficient sanitization, allowing directory traversal.

## Attack Chain

1.  The attacker sends a POST request to the `/api/upload` endpoint without any authentication.
2.  The request body includes a JSON payload with a `destination` field containing a path traversal sequence (e.g., `a/../../../../<target>`).
3.  The `filename` field in the JSON payload specifies the name of the file to be written.
4.  The `resource.data` field contains the base64-encoded content of the file to be written.
5.  The server concatenates the `destination` value with the application directory path without proper sanitization using `path.resolve()`.
6.  The server writes the file specified by `filename` to the attacker-controlled path using `fs.writeFileSync()`.
7.  The attacker writes a malicious file (e.g., a JavaScript file containing code to execute commands) to a known location on the server.
8.  If the uploaded file is a settings.js file, the attacker can achieve RCE on the next application startup by overwriting the existing settings.js file with a malicious one containing Javascript code that executes commands upon loading.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary code on the FUXA server. This can lead to complete system compromise, data theft, or denial of service. The availability of public exploit code significantly increases the likelihood of exploitation. The target application is running on Ubuntu Server.

## Recommendation

*   Apply the patch to upgrade FUXA to version 1.2.10 or later to address CVE-2026-25895.
*   Deploy the Sigma rule "Detect CVE-2026-25895 Exploitation — FUXA Unauthenticated Path Traversal" to detect exploitation attempts.
*   Monitor web server logs for POST requests to `/api/upload` with suspicious path traversal sequences in the `cs-uri-query` or `cs-uri-stem` fields, as described in the Sigma rule and the overview.
*   Implement input validation and sanitization on the `/api/upload` endpoint to prevent path traversal attacks.
*   Enforce authentication and authorization controls on the `/api/upload` endpoint to restrict access to authorized users only.
