---
title: nginx-ui Race Condition Leads to Data Corruption and Potential RCE
slug: 2024-01-08-nginx-ui-race-condition
description: The nginx-ui application is vulnerable to a race condition due to concurrent requests corrupting the app.ini configuration file, potentially leading to a persistent denial of service and a non-deterministic path to remote code execution.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - race-condition
  - nginx-ui
  - denial-of-service
  - remote-code-execution
  - configuration-corruption
vendors:
  - 0xJacky
products:
  - nginx-ui
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-m468-xcm6-fxg4
rules:
  - title: Detect Rapid Settings Updates to nginx-ui
    description: Detects potential exploitation of the race condition vulnerability by monitoring for multiple POST requests to the settings endpoint within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Nginx Reload After Settings Modification
    description: Detects potential RCE by monitoring for suspicious processes invoking the nginx -s reload command after changes to the settings.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Corruption of app.ini Configuration File
    description: Detects potential exploitation of the race condition vulnerability by monitoring for changes to the app.ini file.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - file_event
      - linux
rules_count: 3
---

The `nginx-ui` application, specifically version v2.3.3, is susceptible to a race condition stemming from the lack of synchronization mechanisms and non-atomic file writes within its settings update pipeline. This vulnerability, identified on Kali Linux 6.17.10-1kali1 within a Docker container deployment, arises when multiple concurrent requests modify the primary configuration file (`app.ini`). This leads to memory and file corruption resulting in inconsistent application states. This vulnerability can lead to persistent denial-of-service conditions and, under specific circumstances, introduces a non-deterministic path for achieving remote code execution through the cross-contamination of configuration parameters. Defenders should be aware of the potential for disrupted nginx-ui services, especially in environments with frequent configuration updates.

## Attack Chain

1. An attacker gains access to the nginx-ui dashboard, likely through valid credentials or exploiting an existing vulnerability.
2. The attacker navigates to the settings or preferences section of the nginx-ui.
3. The attacker crafts a POST request to the `/api/settings` endpoint with malicious settings modifications using tools such as Burp Suite.
4. The attacker floods the `/api/settings` endpoint with multiple concurrent requests to trigger the race condition.
5. Due to the lack of synchronization primitives, `ProtectedFill()` modifies shared global singleton pointers in an unsafe manner.
6. Concurrent write operations to `app.ini` interleave, causing file corruption with empty lines, truncated fields, or overwritten configuration keys.
7. The corruption of `app.ini` causes the application to either redirect to the `/install` page or encounter a fatal error during boot, leading to a denial of service.
8. If configuration sections become interleaved (e.g., nginx settings written into webauthn section), an attacker might inject a malicious payload into a command execution field such as `ReloadCmd`, achieving potential remote code execution upon the next nginx reload.

## Impact

The race condition in `nginx-ui` can have significant consequences. The immediate impact is a persistent denial of service, rendering the application unavailable. The corruption of the `app.ini` file leads to loss of configuration integrity, making recovery through the web UI impossible. Furthermore, the potential for cross-contamination of INI values opens a non-deterministic path to remote code execution. Although the conditions for achieving RCE are dependent on the precise interleaving of thread execution, successful exploitation would allow an attacker to execute arbitrary commands on the server.

## Recommendation

*   Apply the patched version of nginx-ui (v2.3.4) available at https://github.com/0xJacky/nginx-ui/releases/tag/v2.3.4 to remediate CVE-2026-33028.
*   Monitor web server logs for multiple, rapid `POST` requests to the `/api/settings` endpoint to detect potential exploitation attempts.
*   Implement a file integrity monitoring (FIM) system to detect unauthorized modifications to the `app.ini` configuration file using file_event logs.
*   Deploy the Sigma rule to detect suspicious processes invoking the `nginx -s reload` command after settings modification to identify potential RCE attempts.
