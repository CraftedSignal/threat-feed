---
title: protobuf.js CLI pbts Command Injection Vulnerability
slug: 2026-05-protobufjs-command-injection
description: The protobuf.js CLI tool `pbts` is vulnerable to OS command injection via crafted filenames or paths with shell metacharacters, potentially leading to arbitrary command execution with the privileges of the `pbts` process when invoked on attacker-influenced file paths; CVE-2026-42290.
date: "2026-05-12T15:00:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - protobufjs
  - cli
  - execution
vendors:
  - npm
products:
  - protobufjs-cli (<= 1.2.0)
  - protobufjs-cli (>= 2.0.0, <= 2.0.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-f84p-cvgm-xgjj
  - CVE-2026-42290
rules:
  - title: Detect CVE-2026-42290 Exploitation Attempt - pbts Command Injection via Filename
    description: Detects potential exploitation of CVE-2026-42290 where the `pbts` command is executed with filenames containing shell metacharacters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-42290 Exploitation Attempt - pbts JSDoc Command Injection
    description: Detects potential exploitation of CVE-2026-42290 where commands involving jsdoc containing shell metacharacters are executed as a child process of pbts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `pbts` command-line tool in protobuf.js is susceptible to OS command injection due to its construction of shell command strings from input file paths when invoking JSDoc. This occurs because file paths containing shell metacharacters are interpreted by the shell rather than being treated as plain arguments by JSDoc. This vulnerability exists in protobufjs-cli versions 1.2.0 and earlier, as well as versions 2.0.0 through 2.0.1. Successful exploitation allows an attacker to execute arbitrary shell commands within the context of the `pbts` process. It is important to note that this issue specifically affects the CLI tooling path; the protobuf.js runtime APIs for encoding, decoding, parsing, and loading protobuf messages remain unaffected. Defenders should focus on monitoring and restricting the usage of `pbts` with untrusted input.

## Attack Chain

1. An attacker gains control over filenames or paths that will be processed by `pbts`.
2. The attacker crafts a malicious filename or path containing shell metacharacters (e.g., `;`, `|`, `&`, `$`).
3. A user or application invokes the vulnerable `pbts` command, passing the attacker-controlled path as an argument.
4. `pbts` constructs a shell command string that includes the malicious path.
5. `pbts` executes the generated command string using `child_process.exec`.
6. The shell interprets the metacharacters in the malicious path, leading to the execution of arbitrary commands.
7. The attacker achieves arbitrary command execution with the privileges of the `pbts` process.
8. The attacker can then perform malicious activities such as data exfiltration, system compromise, or denial of service.

## Impact

Successful exploitation of this vulnerability (CVE-2026-42290) enables an attacker to execute arbitrary shell commands with the privileges of the process running `pbts`. This could lead to complete system compromise, data theft, or other malicious activities. The vulnerable component is the command line tool. The number of potential victims depends on the prevalence of vulnerable protobufjs-cli versions and the degree to which `pbts` is used with untrusted input.

## Recommendation

- Upgrade to a patched version of `protobufjs-cli` that addresses CVE-2026-42290.
- If upgrading is not immediately feasible, sanitize or rename input files before invoking `pbts`, as described in the advisory.
- Implement process monitoring to detect suspicious command execution originating from `pbts` processes, using the process_creation rules provided.
- Run the `pbts` CLI in an isolated environment with minimal privileges to limit the impact of potential command injection attacks, as described in the advisory.
