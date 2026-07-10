---
title: basic-ftp FTP Command Injection via CRLF Characters
slug: 2024-01-09-basic-ftp-crlf
description: "basic-ftp version 5.2.0 is vulnerable to FTP command injection via CRLF sequences in file path parameters passed to path APIs such as cd(), remove(), rename(), uploadFrom(), downloadTo(), list(), and removeDir(). The protectWhitespace() helper only handles leading spaces and returns other paths unchanged, while FtpContext.send() writes the resulting command string directly to the control socket with `\r\n` appended, allowing attacker-controlled path strings to split one intended FTP command into multiple commands."
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ftp
  - command-injection
  - crlf
vendors:
  - basic-ftp
products:
  - basic-ftp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-chqc-8p9q-pq6q
  - https://www.npmjs.com/package/basic-ftp
  - https://github.com/patrickjuchli/basic-ftp
  - https://github.com/patrickjuchli/basic-ftp/blob/master/src/Client.ts
  - https://github.com/patrickjuchli/basic-ftp/blob/master/src/FtpContext.ts
  - https://cwe.mitre.org/data/definitions/93.html
  - https://owasp.org/www-community/vulnerabilities/CRLF_Injection
rules:
  - title: Detect FTP Command Injection via CRLF Sequences
    description: Detects FTP commands containing CRLF sequences, indicating potential command injection.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect basic-ftp CRLF Injection Attempt in Web Logs
    description: Detects attempts to exploit basic-ftp CRLF injection by looking for CRLF sequences in URI queries.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `basic-ftp` npm package, version 5.2.0, contains a command injection vulnerability stemming from improper sanitization of file path parameters. Specifically, the `protectWhitespace()` function fails to neutralize CRLF sequences (`\r\n`), allowing attackers to inject arbitrary FTP commands. The vulnerability exists because the `send()` function in `FtpContext.js` directly writes commands to the control socket with `\r\n` appended. This allows an attacker to craft malicious path strings that, when processed by the affected methods (cd(), remove(), rename(), uploadFrom(), downloadTo(), list(), and removeDir()), result in the execution of unintended FTP commands. This vulnerability impacts applications that use `basic-ftp` to interact with FTP servers and accept user-controlled input for file paths. The vulnerability was confirmed in version 5.2.0, and as of 2026-04-04, no fix is available.

## Attack Chain

1.  An attacker crafts a malicious file path containing CRLF sequences (`\r\n`) and an injected FTP command.
2.  The attacker provides the malicious path as input to one of the vulnerable `basic-ftp` methods, such as `cd()`, `remove()`, `rename()`, `uploadFrom()`, `downloadTo()`, `list()`, or `removeDir()`.
3.  The `protectWhitespace()` function in `Client.js` is called, but it fails to sanitize the CRLF sequences in the path.
4.  The unsanitized path is passed to the `send()` function in `FtpContext.js`, which appends `\r\n` to the command string and writes it to the TCP socket.
5.  The FTP server interprets the CRLF sequences as command delimiters, splitting the intended command into multiple commands.
6.  The injected FTP command is executed by the server. This can include deleting files (`DELE`), creating/removing directories (`MKD`, `RMD`), or triggering downloads (`RETR`).
7.  The attacker potentially hijacks the session by injecting `USER` and `PASS` commands.
8.  The attacker gains unauthorized access to files, directories, or potentially executes arbitrary commands on the FTP server, leading to data exfiltration or service disruption.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, including arbitrary file deletion, directory manipulation, file exfiltration, server command execution (if supported by the FTP server), session hijacking, and service disruption. The vulnerability poses a significant risk to applications that rely on `basic-ftp` and accept user-supplied file paths. If an attacker controls the FTP paths, they can inject arbitrary commands, compromising the confidentiality, integrity, and availability of the FTP server and its data.

## Recommendation

*   Apply the immediate workaround by sanitizing all path inputs before passing them to `basic-ftp`, rejecting paths containing `\r` or `\n` characters. See the provided sanitization example in the mitigation section of this brief.
*   Monitor network connections for FTP traffic containing suspicious commands within file paths, using the provided Sigma rule targeting network connections with CRLF sequences.
*   Upgrade to a patched version of `basic-ftp` as soon as one becomes available that properly sanitizes or rejects CRLF sequences in file paths, addressing the root cause detailed in the overview of this brief.
