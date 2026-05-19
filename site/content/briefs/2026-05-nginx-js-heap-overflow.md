---
title: NGINX JavaScript Heap Buffer Overflow Vulnerability (CVE-2026-8711)
slug: 2026-05-nginx-js-heap-overflow
description: NGINX JavaScript is vulnerable to a heap buffer overflow (CVE-2026-8711) when the js_fetch_proxy directive is configured with client-controlled variables and ngx.fetch(), allowing unauthenticated attackers to cause worker process restarts or, with ASLR disabled, code execution via crafted HTTP requests.
date: "2026-05-19T15:19:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - heap-buffer-overflow
  - nginx
vendors:
  - NGINX
products:
  - NGINX JavaScript
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: 'Indicator Removal on Host: Clear Windows Event Logs'
cves:
  - id: CVE-2026-8711
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8711
rules:
  - title: Detect CVE-2026-8711 Exploitation Attempt — Crafted HTTP Request to js_fetch_proxy
    description: Detects CVE-2026-8711 exploitation attempt — detects crafted HTTP requests with potentially malicious payloads targeting the js_fetch_proxy directive
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-8711 Exploitation Attempt — NGINX Worker Process Restart
    description: Detects CVE-2026-8711 exploitation attempt — detects rapid restarts of the NGINX worker process, potentially indicating a heap buffer overflow.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

NGINX JavaScript is susceptible to a heap buffer overflow vulnerability (CVE-2026-8711). The vulnerability occurs when the `js_fetch_proxy` directive is configured with at least one client-controlled NGINX variable (e.g., `$http_*`, `$arg_*`, `$cookie_*`) and a location invoking the `ngx.fetch()` operation from NGINX JavaScript. An unauthenticated attacker can exploit this vulnerability by sending crafted HTTP requests to the affected NGINX server. Successful exploitation may lead to a heap buffer overflow in the NGINX worker process, resulting in a restart of the process. Furthermore, on systems where Address Space Layout Randomization (ASLR) is disabled, this vulnerability could potentially lead to arbitrary code execution.

## Attack Chain

1. An attacker crafts a malicious HTTP request containing specially crafted data within headers, arguments, or cookies.
2. The attacker sends the crafted HTTP request to the targeted NGINX server.
3. NGINX receives the request and processes it according to the server configuration.
4. The `js_fetch_proxy` directive is triggered due to the request matching a configured location.
5. The `ngx.fetch()` operation is invoked from the NGINX JavaScript code within the triggered location.
6. The JavaScript code utilizes a client-controlled NGINX variable (e.g., `$http_*`, `$arg_*`, `$cookie_*`) as part of the `ngx.fetch()` operation's configuration or parameters.
7. Due to insufficient input validation or sanitization, the crafted data from the client-controlled variable causes a heap buffer overflow during the processing of the `ngx.fetch()` operation.
8. The heap buffer overflow corrupts memory within the NGINX worker process, leading to a process restart, or, with ASLR disabled, potentially code execution.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition due to the NGINX worker process restarting. On systems with ASLR disabled, successful exploitation can lead to arbitrary code execution, potentially allowing the attacker to gain full control of the affected system. The scope of impact depends on the specific configuration of NGINX and the JavaScript code used.

## Recommendation

*   Apply the necessary patch or upgrade to the latest version of NGINX JavaScript to remediate CVE-2026-8711.
*   Review NGINX configurations to identify instances where the `js_fetch_proxy` directive is used with client-controlled variables and `ngx.fetch()`. Implement robust input validation and sanitization to mitigate potential buffer overflows.
*   Enable Address Space Layout Randomization (ASLR) on systems running NGINX to mitigate the risk of code execution in the event of a successful buffer overflow.
*   Deploy the Sigma rules provided below to detect exploitation attempts targeting CVE-2026-8711.
*   Monitor NGINX logs for unusual HTTP requests containing potentially malicious payloads in headers, arguments, or cookies that are being used with the vulnerable directive (see example requests in positive tests below).
