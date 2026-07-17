---
title: ForgeCode AI Pair-Programming CLI Arbitrary Code Execution via Malicious .mcp.json
slug: 2026-07-forgecode-rce
description: CVE-2026-57860 describes an arbitrary code execution vulnerability in ForgeCode, an AI pair-programming CLI tool, where it automatically loads and executes commands specified in a repository's `.mcp.json` file upon startup without user confirmation, allowing attackers to achieve initial access and persistence on developer machines when a user runs `forge` within an untrusted, cloned repository.
date: "2026-07-17T17:23:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-code-execution
  - cli
  - developer-tools
  - supply-chain
vendors:
  - tailcallhq
products:
  - ForgeCode
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: When a user runs the forge CLI inside a cloned untrusted repository, the specified commands are spawned with the invoking user's privileges, resulting in arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'A malicious repository can supply a crafted .mcp.json whose mcpServers entries specify arbitrary command and args values (for example, command: bash with args: [''-c'', ''touch /tmp/pwned'']).'
    confidence_band: high
cves:
  - id: CVE-2026-57860
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57860
rules:
  - title: Detects CVE-2026-57860 Exploitation - ForgeCode Spawning Shell Command
    description: Detects CVE-2026-57860 exploitation where the ForgeCode CLI (forge) spawns a shell process with arbitrary command execution via a malicious .mcp.json file.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

CVE-2026-57860 details a critical arbitrary code execution vulnerability in ForgeCode (tailcallhq/forgecode), an AI pair-programming command-line interface (CLI) tool. This flaw allows malicious actors to achieve initial access and persistence on a developer's system without explicit user confirmation. When a user initializes the `forge` CLI within a repository, the tool automatically parses and executes server definitions from the repository's `.mcp.json` file. A crafted `.mcp.json` can include arbitrary commands and arguments (e.g., `command: bash` with `args: ['-c', 'touch /tmp/pwned']`), which are then executed with the invoking user's privileges. This mechanism provides a reliable attack vector against developers who clone and evaluate untrusted repositories, transforming a seemingly benign action into a compromise opportunity. The vulnerability affects the ForgeCode CLI, commonly used in Linux and macOS development environments.

## Attack Chain

1. An attacker creates a malicious repository containing a specially crafted `.mcp.json` file.
2. The `.mcp.json` file is configured with `mcpServers` entries that specify arbitrary `command` and `args` values, designed to execute malicious code (e.g., `bash -c 'payload'`).
3. The malicious repository is then hosted on a public platform (e.g., GitHub) or distributed to target developers.
4. A victim developer, operating under the assumption of a legitimate code repository, clones the untrusted repository to their local machine.
5. The developer then navigates into the cloned repository's directory and executes the `forge` CLI command.
6. Upon startup, ForgeCode automatically reads and parses the `.mcp.json` file present in the current repository.
7. Without requiring further user confirmation, ForgeCode loads and executes the arbitrary commands defined within the malicious `.mcp.json` file.
8. Arbitrary code is executed on the developer's system with the privileges of the invoking user, leading to initial access, persistence, and potential system compromise.

## Impact

The successful exploitation of CVE-2026-57860 leads to arbitrary code execution on developer workstations. This provides attackers with a reliable initial access vector into development environments, often considered high-value targets due to access to source code, credentials, and build pipelines. The automatic execution on CLI startup also offers a persistence primitive, as the malicious commands would re-execute each time the developer invokes `forge` within the compromised repository. While no specific victim counts are available, any developer using ForgeCode on Linux or macOS who interacts with untrusted repositories is at risk, potentially leading to intellectual property theft, further network compromise, or supply chain attacks.

## Recommendation

* Patch ForgeCode (tailcallhq/forgecode) to a version that addresses CVE-2026-57860 immediately upon availability.
* Implement strong controls and policies against cloning or executing `forge` within untrusted or unverified repositories.
* Deploy the provided Sigma rule to your SIEM to detect suspicious process execution patterns where the `forge` CLI acts as a parent to unexpected shell commands.
* Enable process creation logging for both `linux` and `macos` endpoints to ensure telemetry for detection rules is available.
