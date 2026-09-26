---
title: Unauthenticated Path Traversal in Khoj
slug: 2026-09-khoj-path-traversal
description: An unauthenticated path traversal vulnerability in the Khoj /home/ endpoint allows remote attackers to read arbitrary files from the server filesystem.
date: "2026-09-26T02:07:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - path-traversal
  - information-disclosure
vendors:
  - Khoj
products:
  - khoj (2.0.0-beta.23 - 2.0.0-beta.24)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The endpoint allows file read from server filesystem via directory traversal.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-62mm-xwmv-crhg
rules:
  - title: Detect Path Traversal Attempt in /home/ Endpoint
    description: Detects path traversal attempts directed at the vulnerable Khoj /home/ endpoint by looking for dot-dot-slash patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Khoj to version 2.0.0-beta.25 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory states the vulnerability is resolved in 2.0.0-beta.25
  mitigation_plan:
    - priority: immediate
      action: Block requests to /home/ containing ../ using a WAF
      owner: Security Operations
      addresses: Path traversal exploitation
      evidence: Source identifies /home/ as the vulnerable endpoint
---

The Khoj application contains an unauthenticated path traversal vulnerability within the /home/ endpoint, defined in 'src/khoj/routers/web_client.py'. This endpoint is intended to serve static files from a specific directory but fails to perform path normalization or validation before resolving user-supplied input. An attacker can append directory traversal sequences (such as ../) to the URI to escape the intended directory and access sensitive files on the host filesystem. Because the endpoint lacks authentication decorators, exploitation is possible by any unauthenticated attacker with network access to the Khoj instance. This flaw affects Khoj versions from 2.0.0-beta.23 to 2.0.0-beta.25.

## Attack Chain

1. Attacker performs network reconnaissance to identify a reachable Khoj instance.
2. Attacker interacts with the /home/ endpoint via an HTTP GET request.
3. Attacker crafts a malicious URI containing path traversal sequences (e.g., ../../../etc/passwd).
4. The application logic in 'web_client.py' concatenates the malicious path to the base directory without validation.
5. The underlying operating system resolves the traversal sequences to a target file path outside the web directory.
6. The 'FileResponse' object retrieves the content of the unintended file.
7. The application returns the contents of the requested file in the HTTP response body, leading to information disclosure.

## Impact

Successful exploitation allows unauthenticated remote attackers to read any file on the server accessible to the application process. This includes sensitive data such as database credentials, API keys, application secrets (e.g., Django SECRET_KEY), and system-level files like '/etc/passwd' or '/proc/self/environ'. Access to these files can lead to complete service compromise, facilitate further lateral movement, or allow the attacker to gain persistent unauthorized access to the environment.

## Recommendation

1. Upgrade to a version of Khoj patched against this vulnerability (>= 2.0.0-beta.25).
2. Implement a WAF or reverse proxy rule to block or sanitize incoming HTTP requests containing directory traversal sequences (e.g., ../) in the /home/ URI path.
3. Apply the suggested code-level patch to 'src/khoj/routers/web_client.py' by adding path resolution and validation logic that verifies the requested file remains within the intended base directory.
4. Deploy the suggested Sigma rule to monitor for suspicious traversal patterns in web server logs.
