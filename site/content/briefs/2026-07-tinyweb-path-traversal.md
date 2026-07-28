---
title: TinyWeb Path Traversal Vulnerability (CVE-2026-67185)
slug: 2026-07-tinyweb-path-traversal
description: A path traversal vulnerability, tracked as CVE-2026-67185, exists in TinyWeb through version 0.0.8, allowing unauthenticated attackers to read arbitrary files by submitting '..' sequences in the URL path, bypassing security checks and potentially exposing sensitive data like credential stores or private keys when the server runs with root privileges.
date: "2026-07-28T17:22:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - webserver
  - vulnerability
  - cve
vendors:
  - TinyWeb
products:
  - TinyWeb <= 0.0.8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: TinyWeb through 0.0.8 contains a path traversal vulnerability that allows unauthenticated attackers
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: allows unauthenticated attackers to read arbitrary files by submitting ../ sequences in the URL path
    confidence_band: high
cves:
  - id: CVE-2026-67185
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67185
rules:
  - title: Detects CVE-2026-67185 Exploitation - TinyWeb Path Traversal Attempt
    description: Detects exploitation attempts for CVE-2026-67185, a path traversal vulnerability in TinyWeb, by identifying HTTP GET requests containing directory traversal sequences (../ or ..\) in the URI path.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

TinyWeb, a lightweight web server, is affected by a path traversal vulnerability (CVE-2026-67185) in versions up to and including 0.0.8. This critical flaw allows unauthenticated attackers to read arbitrary files on the server's filesystem. Attackers exploit this by crafting malicious HTTP requests that contain directory traversal sequences (e.g., `../`) within the URL path. The vulnerability stems from improper input validation and sanitation in the `HttpBuilder::buildResponse()` function, which directly concatenates the attacker-controlled URL path with the configured web root without normalization or boundary checks. This allows the crafted path to be passed directly to `HttpFile::setFile()`, enabling access to sensitive files such as `etc/passwd` or private keys if the TinyWeb process operates with elevated privileges, such as root. This vulnerability poses a significant risk for data exposure on vulnerable servers.

## Attack Chain

1. An unauthenticated attacker identifies a TinyWeb server running a vulnerable version (0.0.8 or earlier).
2. The attacker crafts a GET request to the TinyWeb server, embedding directory traversal sequences (`../`) in the URL path. For example, `GET /../../../../etc/passwd HTTP/1.1`.
3. The TinyWeb server receives this HTTP request.
4. The `HttpBuilder::buildResponse()` function processes the incoming URL path.
5. Due to the vulnerability, `HttpBuilder::buildResponse()` directly concatenates the crafted URL path, including the `../` sequences, with the server's configured web root path without proper normalization or sanitization.
6. This improperly formed absolute path is then passed to `HttpFile::setFile()`, which attempts to open and serve the file at the manipulated path.
7. The TinyWeb server reads and returns the content of an arbitrary file (e.g., `/etc/passwd`) to the attacker.
8. The attacker successfully exfiltrates sensitive information from the server's filesystem, potentially including configuration files, credential stores, or private keys, if the server process has sufficient permissions.

## Impact

The successful exploitation of CVE-2026-67185 allows unauthenticated attackers to achieve arbitrary file read capabilities on TinyWeb servers. This can lead to the exposure of highly sensitive information, including system configuration files, user credentials, and private cryptographic keys. If the TinyWeb process runs with elevated privileges, such as the `root` user, the attacker can access any file on the system, significantly increasing the severity of the data breach. The number of potentially affected victims corresponds to the deployment of TinyWeb servers globally, particularly those exposed to the internet. This vulnerability primarily affects web services and any organizations utilizing TinyWeb.

## Recommendation

* Patch CVE-2026-67185 by upgrading TinyWeb to a version beyond 0.0.8 immediately.
* Deploy the Sigma rule provided in this brief to your SIEM to detect attempts at path traversal exploitation against web servers.
* Monitor `webserver` logs for HTTP requests containing directory traversal sequences like `../` or `..\` in the URI stem or query parameters.
* Ensure that the TinyWeb server process runs with the lowest possible privileges to minimize the impact of successful exploitation.
