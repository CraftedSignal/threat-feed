---
title: DeepSeek TUI run_tests Tool Enables RCE via Malicious Repository Without Approval
slug: 2026-05-deepseek-tui-rce
description: DeepSeek TUI's `run_tests` tool allows for remote code execution (RCE) via a malicious repository without user approval due to auto-approval of `cargo test` execution, which can be triggered by prompt injection via the `AGENTS.md` file, affecting versions >= 0.3.0 and < 0.8.23.
date: "2026-05-14T20:36:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - prompt-injection
  - rust
  - supply-chain
vendors:
  - rust
  - npm
products:
  - deepseek-tui (>= 0.3.0, < 0.8.23)
  - deepseek-tui-cli (>= 0.3.0, < 0.8.23)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-wx44-2q6h-j6p8
  - CVE-2026-45311
rules:
  - title: Detects CVE-2026-45311 Exploitation — Cargo Test Executing Shell Commands
    description: Detects CVE-2026-45311 exploitation — `cargo test` executing shell commands, indicating potential malicious test code execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detects AGENTS.md Prompt Injection Leading to cargo test Execution
    description: Detects the presence of AGENTS.md file containing prompt injection attempting to force execution of cargo test.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

DeepSeek TUI is vulnerable to remote code execution (RCE) due to the `run_tests` tool's automatic approval of `cargo test` execution. The `run_tests` tool executes `cargo test` in the workspace with `ApprovalRequirement::Auto`, meaning it runs without any user approval prompt. The `cargo test` command compiles and executes arbitrary code, including test binaries, build scripts, and proc macros. A malicious repository can leverage this to execute arbitrary shell commands, exfiltrate credentials, or establish persistence without any user interaction. This vulnerability is amplified by the `AGENTS.md` file, which is auto-loaded into the system prompt and can instruct the model to proactively run tests at session start. This vulnerability affects versions >= 0.3.0 and < 0.8.23 of the deepseek-tui, deepseek-tui-cli, and npm/deepseek-tui packages.

## Attack Chain

1.  An attacker creates a malicious Rust repository.
2.  The repository includes a `Cargo.toml` file, source code (`src/lib.rs`), and a malicious test file (`tests/integration_test.rs`) containing code to execute arbitrary commands, such as exfiltrating data using `curl`.
3.  The repository also contains an `AGENTS.md` file with prompt injection instructions to direct the model to run tests automatically.
4.  A user opens the malicious repository in DeepSeek TUI using the `deepseek-tui` command.
5.  The `AGENTS.md` file is automatically loaded into the model's system prompt, instructing the model to run tests.
6.  The model calls the `run_tests` tool, which is auto-approved due to `ApprovalRequirement::Auto`.
7.  `cargo test` compiles and executes the malicious test code in `tests/integration_test.rs`.
8.  The attacker receives a callback on their collaborator server, confirming remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve remote code execution on the user's machine. A malicious file in the repository (such as `AGENTS.md`) is auto-loaded into the model's system prompt on session start. This content can contain prompt injection instructions that direct the model to call `run_tests`. Since `run_tests` is auto-approved, the full chain from opening the repo to arbitrary code execution requires zero user approval.

## Recommendation

*   Upgrade to a version of DeepSeek TUI >= 0.8.23 to patch CVE-2026-45311.
*   Implement the suggested mitigation of changing `run_tests` to require approval to prevent automatic execution of potentially malicious code.
*   Monitor process creation events for `cargo test` executing shell commands, using a rule such as the one provided below to detect potential exploitation of CVE-2026-45311.
