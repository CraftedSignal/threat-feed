---
title: Pheditor Authenticated Command Whitelist Bypass via Shell Command Substitution
slug: 2026-07-pheditor-whitelist-bypass
description: Pheditor 2.0.4 contains an authenticated command injection vulnerability, CVE-2026-54540, allowing a user with `terminal` permissions to bypass the `TERMINAL_COMMANDS` whitelist by leveraging shell command substitution to execute arbitrary shell commands as the web server user.
date: "2026-07-16T20:02:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - command-injection
  - php
vendors:
  - Pheditor
products:
  - Pheditor 2.0.4
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The terminal feature ... passes the full command string to `shell_exec()`.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9643-6xjp-vx57
rules:
  - title: Detects CVE-2026-54540 Exploitation - Pheditor Command Whitelist Bypass
    description: Detects exploitation of CVE-2026-54540, an authenticated command injection in Pheditor 2.0.4, where shell command substitution is used to bypass the terminal command whitelist.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.006
    data_sources:
      - webserver
rules_count: 1
---

Pheditor version 2.0.4 is susceptible to an authenticated terminal command whitelist bypass vulnerability, identified as CVE-2026-54540. This flaw allows an attacker with legitimate access and `terminal` permissions to execute arbitrary operating system commands on the underlying web server. The vulnerability stems from how Pheditor's `terminal` feature validates user-submitted commands. While it checks if a command string begins with an entry from a predefined `TERMINAL_COMMANDS` whitelist, it fails to sanitize or block shell command substitution syntax, such as `$()`, before passing the full command directly to the `shell_exec()` PHP function. This permits an authenticated user to append malicious commands using substitution after a whitelisted prefix, effectively circumventing security controls and achieving remote code execution as the web server user. This is critical for deployments where `TERMINAL_COMMANDS` is relied upon to restrict administrative terminal access to a limited set of safe commands.

## Attack Chain

1. An authenticated attacker logs into the Pheditor application with privileges that include `terminal` access.
2. The attacker accesses the terminal feature within the Pheditor application.
3. The attacker crafts a malicious command string that begins with a whitelisted command (e.g., `ls`) and appends a shell command substitution (e.g., `$(arbitrary_command)`).
4. The Pheditor application receives the command via a `POST` request to `pheditor.php` or a similar endpoint.
5. The application performs a prefix check, confirming that the initial part of the attacker's command (e.g., `ls`) matches an entry in the `TERMINAL_COMMANDS` allowlist.
6. Despite the presence of shell metacharacters for command substitution, the application passes the entire, unsanitized command string to the `shell_exec()` PHP function.
7. The underlying operating system shell executes the command, including the arbitrary commands embedded via substitution, leading to remote code execution as the web server user.

## Impact

Successful exploitation of CVE-2026-54540 grants an authenticated attacker the ability to execute arbitrary shell commands as the web server user. This can lead to complete compromise of the Pheditor instance and potentially the underlying server. Attackers could exfiltrate sensitive data, deface the website, install backdoors, or pivot to other systems within the network. This vulnerability is particularly impactful for organizations that deploy Pheditor and rely on the `TERMINAL_COMMANDS` configuration to restrict terminal access to a controlled set of operations, as these restrictions can be trivially bypassed.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect attempts at command substitution in Pheditor's terminal input.
* Monitor `webserver` logs for HTTP POST requests to `pheditor.php` or similar endpoints that contain the `command` parameter with shell command substitution patterns (e.g., `$()`).
* Patch Pheditor to a version greater than 2.0.4, or implement the suggested fixes from the advisory, which include avoiding `shell_exec()` for user-controlled input, requiring exact command matches, or comprehensively rejecting shell metacharacters.
