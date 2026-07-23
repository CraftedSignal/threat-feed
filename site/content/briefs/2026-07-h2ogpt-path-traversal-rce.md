---
title: h2oGPT Path Traversal Vulnerability Leads to Remote Code Execution (CVE-2026-65700)
slug: 2026-07-h2ogpt-path-traversal-rce
description: h2oGPT through version 0.2.1 contains a critical path traversal vulnerability (CVE-2026-65700) in its OpenAI-compatible files API, allowing unauthenticated remote attackers to achieve arbitrary file read, write, and delete, and ultimately remote code execution, by injecting traversal sequences into the bearer token.
date: "2026-07-23T18:28:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - rce
  - api-vulnerability
  - web-vulnerability
  - critical-vulnerability
vendors:
  - h2oGPT
products:
  - h2oGPT 0.2.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: h2oGPT through 0.2.1 contains a path traversal vulnerability in the OpenAI-compatible files API that allows unauthenticated remote attackers to read, write, and delete arbitrary files accessible to the server process by supplying traversal sequences in the bearer token.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: achieve remote code execution by writing to startup hooks or application-loaded files.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: achieve remote code execution by writing to startup hooks or application-loaded files.
    confidence_band: high
cves:
  - id: CVE-2026-65700
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65700
rules:
  - title: Detect CVE-2026-65700 Exploitation Attempt - Path Traversal in Bearer Token
    description: Detects exploitation attempts for CVE-2026-65700, an unauthenticated path traversal vulnerability in h2oGPT's OpenAI-compatible files API, by looking for traversal sequences in the Authorization header's bearer token.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-65700 describes a critical path traversal vulnerability affecting h2oGPT through version 0.2.1. This flaw resides within the OpenAI-compatible files API, specifically in the `get_user_dir` function located in `openai_server/backend_utils.py`. Attackers can exploit this by supplying path traversal sequences (e.g., `../` or `..\`) directly within the bearer token of an HTTP request. Since h2oGPT uses an "EMPTY" default API key, authentication is effectively bypassed, making the vulnerability accessible to unauthenticated remote attackers. Successful exploitation allows for arbitrary file read, write, and deletion, which can be leveraged to write to startup hooks or application-loaded files, thereby achieving remote code execution (RCE) on the underlying server. This poses a significant risk to organizations deploying affected h2oGPT instances.

## Attack Chain

1. An unauthenticated remote attacker sends an HTTP POST request to a vulnerable h2oGPT OpenAI-compatible files API endpoint, such as `/files/upload`, `/files/content`, or `/files/delete`.
2. The attacker crafts the HTTP Authorization header to include a bearer token containing path traversal sequences (e.g., `Bearer ../../../path/to/malicious_file.sh`) to manipulate the file path.
3. Due to the default "EMPTY" API key, the h2oGPT server bypasses authentication checks and proceeds to process the request as if it were legitimate.
4. The `get_user_dir` function in `openai_server/backend_utils.py` is invoked, and it incorrectly incorporates the unsanitized bearer token string into a file path using `os.path.join`.
5. This misconfiguration allows the attacker to specify an arbitrary file path outside the intended user directory, leading to the ability to read, write, or delete files anywhere on the server where the h2oGPT process has write permissions.
6. The attacker uploads or modifies a malicious file (e.g., a web shell, a configuration file with injected commands, or a startup script) to a critical system location.
7. Upon the h2oGPT application restarting, reloading components, or when the tampered file is otherwise executed or loaded, the attacker's injected code achieves remote code execution (RCE) on the server.

## Impact

Successful exploitation of CVE-2026-65700 grants unauthenticated remote attackers arbitrary file read, write, and delete capabilities on the compromised h2oGPT server. This directly leads to remote code execution (RCE) by allowing attackers to inject malicious code into application-loaded files or startup hooks. The consequences include complete compromise of the affected server, potential exfiltration of sensitive data, establishment of persistent backdoors, and lateral movement within the victim's network. Given the unauthenticated nature and the high CVSS score of 9.8, the vulnerability poses a critical threat to the confidentiality, integrity, and availability of systems running vulnerable h2oGPT versions.

## Recommendation

* Patch CVE-2026-65700 immediately by upgrading h2oGPT to a version beyond 0.2.1 to mitigate this critical vulnerability.
* Deploy the Sigma rule `Detect CVE-2026-65700 Exploitation Attempt - Path Traversal in Bearer Token` to your web server logging infrastructure (e.g., Apache, Nginx access logs).
* Monitor web server access logs for HTTP POST requests to OpenAI-compatible API endpoints that contain path traversal sequences (`../`, `..\`) within the `cs-auth-token` field or HTTP Authorization header.
* Ensure that all API keys, including default configurations, are replaced with strong, unique, and non-guessable credentials, and that API key authentication is properly enforced.
