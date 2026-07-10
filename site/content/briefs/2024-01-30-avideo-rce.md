---
title: AVideo Restreamer Endpoint Vulnerability Leads to Remote Code Execution
slug: 2024-01-30-avideo-rce
description: AVideo versions up to 26.0 are vulnerable to remote code execution due to unsanitized user-controlled input in the restreamer endpoint that is passed to shell commands.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - rce
  - command-injection
  - web-application
  - linux
vendors:
  - WWBN AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33648
rules:
  - title: Detect AVideo Restreamer RCE Attempt
    description: Detects attempts to exploit the AVideo RCE vulnerability (CVE-2026-33648) by identifying suspicious POST requests to the /restreamer endpoint containing shell metacharacters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Restreamer RCE Attempt - JSON Body
    description: Detects attempts to exploit the AVideo RCE vulnerability (CVE-2026-33648) by identifying suspicious POST requests to the /restreamer endpoint containing shell metacharacters in JSON body.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1068
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WWBN AVideo, an open-source video platform, is vulnerable to remote command execution (RCE) in versions up to and including 26.0. The vulnerability lies in the restreamer endpoint, where the application constructs a log file path by embedding unsanitized `users_id` and `liveTransmitionHistory_id` values derived from the JSON request body. These attacker-controlled values are then directly concatenated into shell commands, which are subsequently executed using the `exec()` function. This allows an authenticated attacker to inject shell metacharacters such as `$()` or backticks, leading to arbitrary command execution on the server. This vulnerability allows complete compromise of the AVideo server. The patch is available in commit 99b865413172045fef6a98b5e9bfc7b24da11678.

## Attack Chain

1. An authenticated attacker sends a crafted POST request to the `/restreamer` endpoint.
2. The attacker injects shell metacharacters (e.g., `$()`, backticks) into the `users_id` and/or `liveTransmitionHistory_id` parameters within the JSON request body.
3. The AVideo application receives the request and constructs a log file path using the unsanitized input.
4. The application concatenates the malicious log file path into a shell command string.
5. The `exec()` function executes the crafted shell command on the server.
6. The injected shell metacharacters trigger the execution of arbitrary commands on the system.
7. The attacker achieves remote code execution, potentially leading to system compromise.
8. The attacker can then install malware, exfiltrate data, or pivot to other systems.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the AVideo server. This can lead to complete system compromise, including data theft, malware installation, and denial of service. The specific number of affected AVideo instances is unknown, but given its open-source nature, the potential impact is significant if unpatched instances are exposed to the internet. This could affect any organization that uses AVideo as a video platform.

## Recommendation

*   Upgrade AVideo installations to a patched version that includes commit 99b865413172045fef6a98b5e9bfc7b24da11678 to remediate CVE-2026-33648.
*   Implement input validation and sanitization on the `/restreamer` endpoint to prevent shell metacharacter injection, mitigating CVE-2026-33648.
*   Deploy the Sigma rule `Detect AVideo Restreamer RCE Attempt` to identify exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests to `/restreamer` containing shell metacharacters in the request body to identify potential exploitation attempts, helping to mitigate CVE-2026-33648.
