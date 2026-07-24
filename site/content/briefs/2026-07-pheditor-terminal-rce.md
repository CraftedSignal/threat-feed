---
title: Pheditor Terminal Argument Injection Leads to Remote Code Execution
slug: 2026-07-pheditor-terminal-rce
description: A vulnerability in Pheditor's terminal feature (versions <= 2.0.6) allows authenticated attackers to achieve arbitrary command execution via argument injection into allowlisted binaries, which can be chained with default credentials for effective unauthenticated remote code execution on the underlying host.
date: "2026-07-24T21:49:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - argument-injection
  - rce
  - web-application
  - cwe-88
vendors:
  - Pheditor
products:
  - Pheditor (<= 2.0.6)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: a default deployment grants the authenticated access needed to reach the terminal action with a single known credential, making the chain effectively unauthenticated RCE.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
    evidence: '`:617` runs the command through the shell unchanged: `shell_exec((empty($dir) ? null : ''cd '' . escapeshellarg($dir) . '' && '') . $command . '' && echo  ; pwd'')`. So a command beginning with an allowlisted binary, carrying a code-exec flag, and containing none of the rejected characters reaches `shell_exec` intact.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g3hq-hphg-8fhh
rules:
  - title: Pheditor RCE - Detect find Command Argument Injection
    description: Detects CVE-2026-XXXX exploitation (Pheditor RCE) - usage of 'find' command with '-exec' or '-execdir' arguments, which can be injected via the terminal feature to achieve arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Pheditor RCE - Detect git Command Argument Injection
    description: Detects CVE-2026-XXXX exploitation (Pheditor RCE) - usage of 'git' command with '-c' to set an alias that executes arbitrary commands, a known method for argument injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Pheditor RCE - Detect php Command Argument Injection
    description: Detects CVE-2026-XXXX exploitation (Pheditor RCE) - usage of 'php' command with '-r' (run PHP code) followed by suspicious functions or system commands, indicating arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Pheditor RCE - Detect tar Command Argument Injection
    description: Detects CVE-2026-XXXX exploitation (Pheditor RCE) - usage of 'tar' command with '--checkpoint-action' or '--to-command' for arbitrary command execution during archive operations.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 4
---

Pheditor, a web-based code editor, contains a critical vulnerability (CWE-88) in its terminal feature that allows for arbitrary command execution. Affecting versions up to and including 2.0.6, the flaw stems from inadequate validation of arguments passed to allowlisted terminal commands. While the system attempts to restrict commands via a prefix-based allowlist and a denylist for shell metacharacters, it fails to sanitize arguments, permitting injection into binaries like `find`, `git`, `php`, and `tar`. Attackers can append malicious flags (e.g., `-exec` for `find`, `-r` for `php`, `--checkpoint-action` for `tar`) to these binaries, bypassing the allowlist to execute arbitrary code. This exploit leverages existing binaries and does not require shell metacharacters, surviving previous sanitization fixes. When combined with the hardcoded default `admin` password (GHSA-p4h7-p9rj-2pq2), this vulnerability can lead to effective unauthenticated remote code execution with web server privileges, posing a significant risk to Pheditor deployments.

## Attack Chain

1. An unauthenticated attacker gains access to the Pheditor web interface by leveraging the hardcoded default `admin` password, achieving authenticated access.
2. The attacker navigates to the Pheditor's `terminal` action handler, which is designed to execute commands via `shell_exec`.
3. The attacker crafts a malicious command string that begins with an allowlisted binary (e.g., `find`, `git`, `php`, `tar`).
4. The crafted command includes arguments specific to the chosen binary that enable arbitrary command execution (e.g., `find ... -exec`, `git -c alias.x=`, `php -r`, `tar ... --checkpoint-action`).
5. The attacker sends a POST request containing this crafted `command` string to the `terminal` action.
6. Pheditor's `pheditor.php` code performs a prefix match against the `TERMINAL_COMMANDS` allowlist and checks for a denylist of shell metacharacters.
7. Since the command starts with an allowlisted binary and does not contain the forbidden metacharacters, the check passes.
8. The application executes the full crafted command via `shell_exec`, leading to arbitrary command execution on the host with the web server's privileges.

## Impact

Successful exploitation of this vulnerability results in arbitrary command execution on the host system, operating under the privileges of the web server process. This allows attackers to completely compromise the underlying server, leading to data exfiltration, modification, or deletion, installation of additional malware (e.g., backdoors, cryptocurrency miners), or complete system takeover. When combined with the hardcoded default `admin` password, this flaw effectively becomes an unauthenticated remote code execution vector, dramatically increasing its severity and the attack surface for default Pheditor installations.

## Recommendation

* Immediately update Pheditor to a patched version that correctly validates terminal command arguments or remove the application from production if no patch is available.
* Implement robust input validation for all user-supplied command arguments, ensuring that only expected values and structures are permitted.
* If Pheditor is deployed, change the default `admin` password immediately to mitigate unauthorized access to the `terminal` feature, as documented in GHSA-p4h7-p9rj-2pq2.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect attempts at argument injection via the `find`, `git`, `php`, and `tar` commands.
* Enable `process_creation` logging for Linux systems to capture command-line arguments, which is essential for activating the rules above.
