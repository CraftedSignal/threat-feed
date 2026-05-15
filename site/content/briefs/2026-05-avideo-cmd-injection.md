---
title: AVideo OS Command Injection via Unescaped m3u8 URL (CVE-2026-45578)
slug: 2026-05-avideo-cmd-injection
description: AVideo is vulnerable to OS command injection (CVE-2026-45578) in the `on_publish.php` file due to improper sanitization of the m3u8 URL, allowing attackers to execute arbitrary commands by injecting shell metacharacters.
date: "2026-05-15T18:34:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command injection
  - avideo
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-xw67-cg5f-4m2r
  - CVE-2026-45578
rules:
  - title: Detect AVideo on_publish.php Command Injection Attempt
    description: Detects CVE-2026-45578 exploitation — HTTP POST to /plugin/Live/on_publish.php with shell metacharacters in the name parameter indicating a command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
  - title: Detect AVideo on_publish.php Socket Notification Process Creation
    description: Detects process creation events where the on_publish_socket_notification.php script is executed with suspicious arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

AVideo, a video-sharing platform, is susceptible to a critical OS command injection vulnerability (CVE-2026-45578) within the `on_publish.php` file. The issue stems from constructing a command line for `execAsync()` by directly concatenating strings, single-quoting arguments without proper escaping using `escapeshellarg()`. This flaw, located in the YPTSocket notification branch of the Live plugin, enables a malicious actor to inject arbitrary commands by embedding a single quote (`'`) within the `$m3u8` URL or other command parameters. Successful exploitation allows the attacker to execute arbitrary OS commands with the privileges of the web server runtime user. This vulnerability affects AVideo versions up to and including 29.0. The lack of input sanitization and direct web accessibility to `on_publish.php` are key factors enabling this attack.

## Attack Chain

1. Attacker gains a `canStream` account on the AVideo platform.
2. Attacker crafts a malicious stream key containing a single quote and shell metacharacters (e.g., `evilkey';id>/tmp/pwn;#`) and persists it via `saveLive.php`.
3. Attacker sends a POST request directly to `https://target/plugin/Live/on_publish.php` with the crafted stream key in the `name` parameter and a valid password in the `p` parameter.
4. `on_publish.php` processes the POST request, strips `&` and `=`, but permits the single quote and other shell metacharacters in the stream key.
5. `Live::getM3U8File` constructs the m3u8 URL with the injected payload (e.g., `https://server/live/evilkey';id>/tmp/pwn;#.m3u8`).
6. The command string is built using string concatenation without proper escaping, resulting in a vulnerable command.
7. `execAsync()` executes the command, leading to OS command injection.
8. Attacker achieves arbitrary OS command execution with the privileges of the web server user.

## Impact

Successful exploitation of this vulnerability (CVE-2026-45578) grants the attacker the ability to execute arbitrary OS commands on the AVideo server. This could lead to several consequences, including unauthorized access to sensitive data such as database credentials, exfiltration of user information, deployment of a webshell for persistent access, lateral movement to other plugin credentials (PayPal/Stripe API keys, AWS keys), or privilege escalation via local sudoers entries. The impact is significant, potentially leading to complete compromise of the AVideo platform.

## Recommendation

*   Apply the provided patch that utilizes `escapeshellarg()` on all variables interpolated into the command string in `plugin/Live/on_publish.php` to prevent shell injection (see code diff in Overview).
*   Implement an `.htaccess` or nginx `location` rule to restrict access to `/plugin/Live/on_publish.php` to `127.0.0.1` and authorized RTMP server IPs as a defense-in-depth measure (see Overview).
*   Deploy the Sigma rule "Detect AVideo on_publish.php Command Injection Attempt" to identify potential exploitation attempts by monitoring for POST requests to `on_publish.php` with shell metacharacters in the `name` parameter (see Rules).
*   Enable webserver logging to capture HTTP requests, which are essential for detecting and investigating exploitation attempts (see Rules - logsource).
