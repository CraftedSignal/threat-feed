---
title: '@mobilenext/mobile-mcp Path Traversal Vulnerability'
slug: 2024-01-04-mobile-mcp-path-traversal
description: The @mobilenext/mobile-mcp package before version 0.0.49 is vulnerable to a Path Traversal vulnerability in the mobile_save_screenshot and mobile_start_screen_recording tools where the `saveTo` and `output` parameters are passed directly to filesystem operations without validation, potentially allowing an attacker to write files outside the intended workspace, leading to privilege escalation and persistence by overwriting sensitive host files.
date: "2026-03-27T19:13:17Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - path-traversal
  - file-write
  - privilege-escalation
  - persistence
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-3p2m-h2v6-g9mx
rules:
  - title: Detect Mobile-MCP Path Traversal Attempts
    description: Detects attempts to exploit the path traversal vulnerability in @mobilenext/mobile-mcp by monitoring for calls to 'mobile_save_screenshot' or 'mobile_start_screen_recording' with suspicious file paths.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect Mobile-MCP Arbitrary File Write via API Call
    description: Detects attempts to write arbitrary files by monitoring API calls with base64 encoded command lines or shell commands.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `@mobilenext/mobile-mcp` npm package, versions prior to 0.0.49, contains a critical path traversal vulnerability. This flaw stems from the `mobile_save_screenshot` and `mobile_start_screen_recording` tools which improperly handle user-supplied paths. Specifically, the `saveTo` parameter in `mobile_save_screenshot` and the `output` parameter in `mobile_start_screen_recording` are passed directly to filesystem write operations without adequate validation. This oversight enables a malicious actor to write arbitrary files to locations outside of the intended workspace. A successful exploit of this vulnerability allows for the potential overwriting of sensitive system files, enabling privilege escalation and persistence on the host system.

## Attack Chain

1. An attacker gains control over the `saveTo` or `output` parameter of the vulnerable functions. This could be achieved through a malicious application, supply chain attack, or other means of code injection.
2. The attacker crafts a path containing traversal sequences (e.g., `../`) designed to navigate outside of the intended save directory.
3. The attacker calls the `mobile_save_screenshot` or `mobile_start_screen_recording` tool with the manipulated path as the `saveTo` or `output` parameter, respectively.
4. The vulnerable function passes the attacker-controlled path to `fs.writeFileSync()` without validation.
5. `fs.writeFileSync()` writes the screenshot or screen recording data to the attacker-specified path.
6. If the path leads to a sensitive system file (e.g., `~/.bashrc`, `~/.ssh/authorized_keys`), it is overwritten with the contents of the screenshot or screen recording.
7. The attacker can overwrite configuration files or executables in order to achieve code execution.
8. The attacker achieves persistence and/or elevated privileges on the system.

## Impact

Successful exploitation of this path traversal vulnerability can have severe consequences. An attacker can overwrite critical system files, such as shell configuration files (`.bashrc`, `.zshrc`), SSH authorized keys (`.ssh/authorized_keys`), or application configuration files. This can lead to arbitrary code execution, privilege escalation, and persistent backdoor access to the affected system. The reported impact includes potential for a broken shell and unauthorized access. All users of `@mobilenext/mobile-mcp` versions prior to 0.0.49 are vulnerable.

## Recommendation

*   Upgrade to `@mobilenext/mobile-mcp` version 0.0.49 or later to remediate the vulnerability.
*   Implement robust input validation for all file paths used in file system operations. Specifically, validate the `saveTo` and `output` parameters of the `mobile_save_screenshot` and `mobile_start_screen_recording` functions.
*   Deploy the Sigma rule "Detect Mobile-MCP Path Traversal Attempts" to your SIEM to detect attempts to exploit this vulnerability.
*   Monitor application logs for unusual file access patterns or attempts to write to sensitive system directories.
