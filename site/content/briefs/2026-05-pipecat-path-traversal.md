---
title: Pipecat Path Traversal Vulnerability in `/files` Endpoint (CVE-2026-44716)
slug: 2026-05-pipecat-path-traversal
description: Pipecat's development runner has a path traversal vulnerability in the `/files` endpoint due to lack of input validation when handling the filename parameter, allowing an unauthenticated attacker with network access to read arbitrary files on the server using `%2F`-encoded separators.
date: "2026-05-15T16:55:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - python
  - cve-2026-44716
vendors:
  - pipecat-ai
products:
  - pipecat-ai (>= 0.0.90, < 1.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-3363-2ph6-35wh
rules:
  - title: Detect Pipecat Path Traversal Attempt via URL Encoding
    description: Detects CVE-2026-44716 exploitation — attempts to exploit path traversal in Pipecat's /files endpoint by using %2F-encoded characters in the URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Pipecat Runner Folder Access
    description: Detects access to the /files endpoint of a Pipecat runner, indicating potential exploitation attempts.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A path traversal vulnerability exists in Pipecat's development runner (`src/pipecat/runner/run.py`) within the `/files` endpoint. When the runner is started with the `--folder` flag, it exposes a `GET /files/{filename:path}` endpoint. The `filename` path parameter is vulnerable to directory traversal because it's directly concatenated with `args.folder` without proper sanitization. Starlette's path normalization is bypassed using `%2F`-encoded slashes. An attacker can read any file the pipecat process has permission to access, including SSH private keys, credentials, and system files, with a single unauthenticated HTTP request. This vulnerability affects pipecat-ai versions >= 0.0.90 and < 1.2.0, and has been confirmed on version 1.1.0.

## Attack Chain

1.  The Pipecat runner is started with the `--folder` option, specifying a directory for file downloads.
2.  The runner exposes a `GET /files/{filename:path}` endpoint.
3.  The attacker crafts a malicious URL with `%2F`-encoded directory separators (e.g., `..%2F..%2Fetc%2Fpasswd`).
4.  The attacker sends an unauthenticated HTTP GET request to the runner's `/files` endpoint with the crafted URL.
5.  Starlette's router matches the route, and the `%2F`-encoded characters are decoded within the `filename` parameter *after* routing.
6.  The application concatenates the decoded `filename` parameter with the `--folder` path without proper validation or sanitization.
7.  The `os.path.exists()` check succeeds because the resolved path (e.g., `/etc/passwd`) exists on the system.
8.  The requested file content is returned in the HTTP response, allowing the attacker to read arbitrary files.

## Impact

Successful exploitation allows an attacker with network access to the runner to read arbitrary files on the server. This includes sensitive information such as SSH private keys, application credentials, `.env` files, database files, and system files (e.g., `/etc/passwd`). In LAN deployments where the runner is exposed on the local network, any host can exploit this without credentials, leading to potential data breaches and system compromise.

## Recommendation

*   Apply the remediation steps outlined in the advisory by patching or upgrading pipecat-ai to version 1.2.0 or later to resolve CVE-2026-44716.
*   Deploy the Sigma rule "Detect Pipecat Path Traversal Attempt via URL Encoding" to identify exploitation attempts in web server logs.
*   Monitor network traffic for HTTP requests to the `/files` endpoint containing `%2F`-encoded characters in the URL to detect potential path traversal attacks.
