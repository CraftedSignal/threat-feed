---
title: AVideo OS Command Injection Vulnerability (CVE-2026-33482)
slug: 2024-01-30-avideo-command-injection
description: AVideo versions up to 26.0 are vulnerable to OS command injection due to insufficient sanitization of shell metacharacters in the `sanitizeFFmpegCommand()` function, potentially allowing arbitrary command execution.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - avideo
  - command-injection
  - cve-2026-33482
  - webserver
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33482
rules:
  - title: Detect AVideo Command Injection Attempt
    description: Detects attempts to exploit the AVideo command injection vulnerability by looking for shell metacharacters, specifically '$()', in requests to the vulnerable function.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Command Injection Exploit (POST Request)
    description: Detects potential command injection attempts in AVideo by identifying POST requests to the vulnerable endpoint containing the `'$()'` sequence, indicative of bash command substitution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, an open-source video platform, contains an OS command injection vulnerability (CVE-2026-33482) affecting versions up to and including 26.0. The vulnerability resides within the `sanitizeFFmpegCommand()` function located in `plugin/API/standAlone/functions.php`. This function is intended to prevent OS command injection in ffmpeg commands by stripping dangerous shell metacharacters. However, it fails to properly sanitize the `$()` bash command substitution syntax. This oversight allows attackers who can craft a valid encrypted payload to achieve arbitrary command execution on the standalone encoder server due to the use of `sh -c` within `execAsync()`. The vulnerability was patched in commit 25c8ab90269e3a01fb4cf205b40a373487f022e1. Exploitation requires the attacker to be able to craft a valid encrypted payload.

## Attack Chain

1. An attacker crafts a malicious encrypted payload containing a command injection payload leveraging the `$()` bash command substitution.
2. The attacker uploads or injects this payload into the AVideo platform.
3. AVideo processes the malicious payload, passing it to the `sanitizeFFmpegCommand()` function.
4. The `sanitizeFFmpegCommand()` function fails to properly sanitize the `$()` bash command substitution syntax within the payload.
5. The unsanitized command is then executed within a double-quoted `sh -c` context in the `execAsync()` function.
6. The `sh -c` interpreter executes the injected command, resulting in arbitrary code execution on the standalone encoder server.
7. The attacker gains control of the server, potentially leading to data exfiltration, system compromise, or further lateral movement.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the AVideo standalone encoder server. This can lead to complete system compromise, including data exfiltration, modification, or deletion. Given the nature of AVideo as a video platform, attackers could also inject malicious content into videos served by the platform, potentially affecting a large number of users.

## Recommendation

*   Apply the patch from commit 25c8ab90269e3a01fb4cf205b40a373487f022e1 to remediate CVE-2026-33482.
*   Deploy the Sigma rule "Detect AVideo Command Injection Attempt" to detect potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests containing shell metacharacters, especially `$()`, targeting the `plugin/API/standAlone/functions.php` path.
