---
title: basic-ftp CRLF Injection Vulnerability Allows Arbitrary FTP Command Execution
slug: 2024-01-02-basic-ftp-crlf-injection
description: The basic-ftp npm package (<= 5.2.1) is vulnerable to CRLF injection, enabling attackers to inject arbitrary FTP commands via crafted credentials or MKD commands, leading to file manipulation, server command execution, and potential session hijacking.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - crlf-injection
  - ftp
  - command-injection
  - nodejs
vendors:
  - basic-ftp
products:
  - basic-ftp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550.004
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/advisories/GHSA-6v7q-wjvx-w8wg
rules:
  - title: Detect basic-ftp CRLF Injection in FTP Commands
    description: Detects FTP commands containing CRLF injection attempts based on network traffic.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - network_connection
      - windows
  - title: Detect MKD Command with CRLF Injection via Network Traffic
    description: Detects MKD commands with CRLF injection attempts based on network traffic. It looks for MKD commands containing encoded or unencoded CRLF characters.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The basic-ftp npm package, versions 5.2.1 and earlier, contains an incomplete CRLF injection protection mechanism. This vulnerability allows attackers to inject arbitrary FTP commands into the control connection by bypassing the existing `protectWhitespace()` control. There are two primary attack vectors: the first involves injecting commands via the `login()` method by manipulating user-supplied credentials, and the second exploits a TOCTOU (Time-of-Check Time-of-Use) race condition in the `_openDir()` method. The vulnerability stems from the direct concatenation of user inputs into FTP commands without proper validation for CRLF characters (\r\n). Successful exploitation can lead to unauthorized file deletion, modification, and execution of arbitrary server commands. Applications that rely on basic-ftp and accept user-provided FTP credentials or paths are at high risk.

## Attack Chain

1. Attacker identifies a target application using basic-ftp (<= 5.2.1) that accepts user-controlled FTP credentials or paths.
2. Attacker crafts a malicious username or password containing CRLF sequences followed by FTP commands, such as `anonymous\r\nDELE important.txt`.
3. The target application passes the crafted credentials to the `login()` method in basic-ftp.
4. The `login()` method concatenates the malicious username and password into USER and PASS commands without validation.
5. basic-ftp sends the crafted FTP commands to the FTP server. The injected command (e.g., `DELE important.txt`) executes before the PASS command.
6. Alternatively, the attacker crafts a malicious directory path containing CRLF sequences followed by FTP commands, such as `test\r\nDELE important.txt/subdir`.
7. The target application passes the crafted path to the `ensureDir()` method, which calls `_openDir()`.
8. The `_openDir()` method sends an MKD command with the crafted path without validation. The injected command (e.g., `DELE important.txt`) executes.

## Impact

Successful exploitation of this CRLF injection vulnerability can lead to several severe consequences. Attackers can delete or manipulate files on the FTP server by injecting `DELE`, `RNFR`, and `RNTO` commands. They can also create or remove directories using `MKD` and `RMD`. Furthermore, attackers can execute arbitrary server commands by injecting `SITE` commands, potentially changing file permissions (e.g., `SITE CHMOD`). In the case of credential injection, the attacker might be able to perform actions with default server permissions before proper authentication occurs. Applications that handle user-supplied FTP credentials, like web-based file managers, are prime targets.

## Recommendation

*   Apply the recommended fix from the advisory by upgrading basic-ftp to a version greater than 5.2.1 or implementing CRLF validation as described in the advisory to prevent command injection in the `login()` and `_openDir()` methods.
*   Deploy the provided Sigma rule "Detect basic-ftp CRLF Injection in FTP Commands" to monitor for FTP commands containing CRLF characters in network traffic.
*   Enable network connection logging to capture FTP traffic for analysis and detection, as required by the Sigma rule.
